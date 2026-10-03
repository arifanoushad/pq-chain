// UI/utils/bundleStore.js
//
// Durable off-chain storage for multi-signature bundles (JISA R1.4).
//
// ─── Design ─────────────────────────────────────────────────────────────
// Only bundleHash = SHA-256(canonical bundle bytes) is written on-chain
// (Fabric and Besu).  The bundle bytes themselves are stored here:
//   - on every configured IPFS node as a single raw block, and pinned.
//     The CID is CIDv1(raw, sha2-256) of the bytes, so it is derived from
//     the on-chain bundleHash and no extra on-chain field is needed;
//   - in a local archive directory (<archiveDir>/<hash>.bin).
//
// put() succeeds only if at least `minReplicas` IPFS nodes stored and
// pinned the block (default: all configured nodes) and the archive write
// succeeded.  get() tries IPFS first, then the archive, and returns bytes
// only if SHA-256(bytes) equals the requested bundleHash.
//
// Configuration (environment):
//   BUNDLE_IPFS_URLS      comma-separated IPFS HTTP API URLs
//                         (default http://127.0.0.1:5001; set to "" for archive-only)
//   BUNDLE_MIN_REPLICAS   minimum IPFS nodes that must pin (default: all)
//   BUNDLE_ARCHIVE_DIR    archive directory (default UI/data/bundles)

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const DEFAULT_ARCHIVE = path.resolve(__dirname, '../data/bundles');
const DEFAULT_IPFS    = 'http://127.0.0.1:5001';
const MAX_BLOCK_BYTES = 1024 * 1024;   // IPFS default block size limit

// ─── CID helpers ─────────────────────────────────────────────────────────

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

function base32(bytes) {
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
        value = (value << 8) | b;
        bits += 8;
        while (bits >= 5) {
            out += BASE32[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
    return out;
}

function normalizeHash(bundleHash) {
    const hex = String(bundleHash).toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`bundleStore: invalid bundleHash ${bundleHash}`);
    return hex;
}

/** CIDv1, raw codec (0x55), sha2-256 multihash (0x12, 32 B), base32 multibase ('b'). */
function cidFromBundleHash(bundleHash) {
    const digest = Buffer.from(normalizeHash(bundleHash), 'hex');
    return 'b' + base32(Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), digest]));
}

function sha256Hex(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}

// ─── BundleStore ─────────────────────────────────────────────────────────

class BundleStore {
    /**
     * @param {Object}   [opts]
     * @param {string[]} [opts.ipfsUrls]     - IPFS HTTP API URLs
     * @param {Object[]} [opts.ipfsClients]  - pre-built clients (tests); overrides ipfsUrls
     * @param {number}   [opts.minReplicas]
     * @param {string}   [opts.archiveDir]
     * @param {number}   [opts.timeoutMs]    - per-IPFS-call timeout (default 30 s)
     */
    constructor(opts = {}) {
        const envUrls = process.env.BUNDLE_IPFS_URLS;
        this.ipfsUrls = opts.ipfsUrls ||
            (envUrls !== undefined ? envUrls.split(',').map(s => s.trim()).filter(Boolean) : [DEFAULT_IPFS]);

        if (opts.ipfsClients) {
            this.ipfs = opts.ipfsClients.map((client, i) => ({ label: `ipfs#${i}`, client }));
        } else if (this.ipfsUrls.length) {
            const { create } = require('ipfs-http-client');
            this.ipfs = this.ipfsUrls.map(url => ({ label: url, client: create({ url }) }));
        } else {
            this.ipfs = [];
        }

        // BUNDLE_MIN_REPLICAS applies only to nodes configured from the
        // environment; explicitly passed nodes default to "all of them".
        const envMin = process.env.BUNDLE_MIN_REPLICAS;
        const fromEnv = !opts.ipfsUrls && !opts.ipfsClients;
        this.minReplicas = opts.minReplicas ??
            (fromEnv && envMin !== undefined ? Number(envMin) : this.ipfs.length);
        if (this.minReplicas > this.ipfs.length) {
            throw new Error(`bundleStore: minReplicas=${this.minReplicas} but only ${this.ipfs.length} IPFS node(s) configured`);
        }

        this.archiveDir = opts.archiveDir || process.env.BUNDLE_ARCHIVE_DIR || DEFAULT_ARCHIVE;
        this.timeoutMs  = opts.timeoutMs || 30_000;
    }

    /**
     * Store canonical bundle bytes durably.
     * @returns {Promise<Object>} { bundleHash, cid, size, pinnedOn, archivePath, latencyMs }
     */
    async put(bytes) {
        const t0 = Date.now();
        const buf = Buffer.from(bytes);
        if (buf.length === 0 || buf.length > MAX_BLOCK_BYTES) {
            throw new Error(`bundleStore.put: bundle size ${buf.length} B outside 1..${MAX_BLOCK_BYTES}`);
        }
        const hex = sha256Hex(buf);
        const cid = cidFromBundleHash(hex);

        const archivePath = this._archive(hex, buf);

        const results = await Promise.allSettled(this.ipfs.map(({ label, client }) =>
            this._withTimeout((async () => {
                const got = await client.block.put(buf, {
                    searchParams: { 'cid-codec': 'raw', mhtype: 'sha2-256' }
                });
                if (got.toString() !== cid) {
                    throw new Error(`${label} returned CID ${got} but expected ${cid}`);
                }
                await client.pin.add(cid);
                return label;
            })(), `ipfs put on ${label}`)
        ));
        const pinnedOn = results.filter(r => r.status === 'fulfilled').map(r => r.value);
        const errors   = results.filter(r => r.status === 'rejected').map(r => r.reason?.message || String(r.reason));

        if (pinnedOn.length < this.minReplicas) {
            throw new Error(`bundleStore.put: pinned on ${pinnedOn.length}/${this.minReplicas} required IPFS nodes: ${errors.join('; ')}`);
        }

        return {
            bundleHash: '0x' + hex,
            cid,
            size: buf.length,
            pinnedOn,
            errors,
            archivePath,
            latencyMs: Date.now() - t0
        };
    }

    /**
     * Fetch bundle bytes by their on-chain bundleHash, verifying SHA-256.
     * @returns {Promise<Object>} { bytes, source, cid, attempts }
     */
    async get(bundleHash) {
        const hex = normalizeHash(bundleHash);
        const cid = cidFromBundleHash(hex);
        const attempts = [];

        for (const { label, client } of this.ipfs) {
            try {
                const bytes = Buffer.from(await this._withTimeout(client.block.get(cid), `ipfs get on ${label}`));
                if (sha256Hex(bytes) === hex) return { bytes, source: label, cid, attempts };
                attempts.push(`${label}: hash mismatch`);
            } catch (e) {
                attempts.push(`${label}: ${e.message}`);
            }
        }

        const file = path.join(this.archiveDir, `${hex}.bin`);
        if (fs.existsSync(file)) {
            const bytes = fs.readFileSync(file);
            if (sha256Hex(bytes) === hex) return { bytes, source: 'archive', cid, attempts };
            attempts.push('archive: hash mismatch');
        } else {
            attempts.push('archive: not found');
        }

        throw new Error(`bundleStore.get: no copy of ${cid} matches bundleHash (${attempts.join('; ')})`);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    _archive(hex, buf) {
        fs.mkdirSync(this.archiveDir, { recursive: true });
        const file = path.join(this.archiveDir, `${hex}.bin`);
        if (fs.existsSync(file) && sha256Hex(fs.readFileSync(file)) === hex) return file;
        const tmp = `${file}.${process.pid}.tmp`;
        fs.writeFileSync(tmp, buf);
        fs.renameSync(tmp, file);
        return file;
    }

    _withTimeout(promise, label) {
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(`${label} timed out after ${this.timeoutMs}ms`)), this.timeoutMs);
        });
        return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    }
}

BundleStore.cidFromBundleHash = cidFromBundleHash;
BundleStore.MAX_BLOCK_BYTES   = MAX_BLOCK_BYTES;

module.exports = BundleStore;
