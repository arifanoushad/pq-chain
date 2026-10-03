// UI/test-scripts/measure-encryption.js
//
// WP3 (R1.3 / R2.W3): cost of encrypt-before-IPFS as a function of file size.
// For each size (random file, generated once): per iteration
//   encrypt   - encryptFile: AES-256-GCM stream + SHA-256 + ML-KEM-768 wrap for 2 recipients
//   wrap      - the 2 ML-KEM-768 key wraps alone (part of encrypt)
//   decrypt   - decryptFile for one recipient: unwrap + AES-256-GCM + SHA-256 check
//   ipfsPlain - add + pin of the plaintext on every IPFS node (baseline, as before WP3)
//   ipfsEnc   - storeEncryptedEvidence: encrypt + add + pin ciphertext and envelope on every node
// Warm-up iterations are discarded. Timer: performance.now().
//
// Run:  cd UI && node test-scripts/measure-encryption.js
// Env:  ENC_SIZES_MB (default 1,10,100,1024), ENC_ITER (default 20),
//       ENC_ITER_LARGE (iterations for sizes >= 100 MB, default 5), ENC_WARMUP (default 1),
//       BUNDLE_IPFS_URLS (default the three local replicas), ENC_TMP (temp dir)

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { performance } = require('perf_hooks');
const { create } = require('ipfs-http-client');

const pqSeal = require('../utils/pqSeal');
const enc    = require('../utils/evidenceEncryption');

const SIZES_MB   = (process.env.ENC_SIZES_MB || '1,10,100,1024').split(',').map(Number);
const ITER       = Number(process.env.ENC_ITER) || 20;
const ITER_LARGE = Number(process.env.ENC_ITER_LARGE) || 5;
const WARMUP     = Number(process.env.ENC_WARMUP ?? 1);
const URLS = (process.env.BUNDLE_IPFS_URLS ?? 'http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003')
    .split(',').map(s => s.trim()).filter(Boolean);

function stats(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const p95  = sorted[Math.floor(arr.length * 0.95)] ?? sorted[sorted.length - 1];
    const std  = Math.sqrt(arr.map(x => (x - mean) ** 2).reduce((a, b) => a + b, 0) / arr.length);
    return { mean, p95, std, min: sorted[0], max: sorted[sorted.length - 1], n: arr.length };
}
async function timed(fn) { const t0 = performance.now(); const v = await fn(); return { v, ms: performance.now() - t0 }; }

async function writeRandomFile(file, bytes) {
    const fd = fs.openSync(file, 'w');
    const chunk = 8 * 1024 * 1024;
    for (let off = 0; off < bytes; off += chunk) fs.writeSync(fd, crypto.randomBytes(Math.min(chunk, bytes - off)));
    fs.closeSync(fd);
}

async function addPlain(clients, file) {
    for (const c of clients) {
        const { cid } = await c.add(fs.createReadStream(file), { cidVersion: 1, rawLeaves: true });
        await c.pin.add(cid.toString());
    }
}

(async () => {
    const tmp = fs.mkdtempSync(path.join(process.env.ENC_TMP || os.tmpdir(), 'pqchain-encbench-'));
    const clients = URLS.map(url => create({ url }));
    await Promise.all(clients.map(c => c.version()));
    const keys = { PoliceOrg: await pqSeal.generateKeyPair(), CourtOrg: await pqSeal.generateKeyPair() };
    const recipients = Object.fromEntries(Object.entries(keys).map(([o, k]) => [o, { kemPublicKey: k.publicKey }]));
    const rows = [];

    console.log(`IPFS replicas: ${URLS.length}; warm-up ${WARMUP}; iterations ${ITER} (<100 MB) / ${ITER_LARGE} (>=100 MB)\n`);
    console.log('size(MB) │ encrypt(ms) wrap(ms) decrypt(ms) │ ipfsPlain(ms) ipfsEnc(ms) overhead');
    for (const mb of SIZES_MB) {
        const bytes = mb * 1024 * 1024;
        const plain = path.join(tmp, `plain-${mb}.bin`);
        await writeRandomFile(plain, bytes);
        const n = mb >= 100 ? ITER_LARGE : ITER;
        const m = { encrypt: [], wrap: [], decrypt: [], ipfsPlain: [], ipfsEnc: [] };

        for (let i = 0; i < WARMUP + n; i++) {
            // New content per iteration so IPFS never deduplicates an earlier add
            const fd = fs.openSync(plain, 'r+'); fs.writeSync(fd, crypto.randomBytes(32), 0, 32, 0); fs.closeSync(fd);
            const id = `ENCBENCH-${mb}-${i}-${Date.now()}`;
            const ctPath = path.join(tmp, 'ct.bin'), outPath = path.join(tmp, 'out.bin');

            const e = await timed(() => enc.encryptFile(plain, ctPath, { evidenceId: id, recipients }));
            const w = await timed(async () => {
                for (const o of Object.keys(recipients)) await pqSeal.seal(recipients[o].kemPublicKey, crypto.randomBytes(32), `${id}|${o}`, 'evidence-data-key');
            });
            const d = await timed(() => enc.decryptFile(ctPath, outPath, e.v, { recipient: 'CourtOrg', kemSecretKey: keys.CourtOrg.secretKey }));
            fs.rmSync(ctPath, { force: true }); fs.rmSync(outPath, { force: true });
            const p = await timed(() => addPlain(clients, plain));
            const s = await timed(() => enc.storeEncryptedEvidence(clients, plain, { evidenceId: id + '-s', recipients, workDir: tmp }));

            if (i >= WARMUP) {
                m.encrypt.push(e.ms); m.wrap.push(w.ms); m.decrypt.push(d.ms); m.ipfsPlain.push(p.ms); m.ipfsEnc.push(s.ms);
            }
        }
        fs.rmSync(plain, { force: true });
        const row = { sizeMB: mb, bytes, iterations: n, ...Object.fromEntries(Object.entries(m).map(([k, v]) => [k, stats(v)])) };
        row.overheadVsPlainIpfs = row.ipfsEnc.mean / row.ipfsPlain.mean - 1;
        rows.push(row);
        console.log(`${String(mb).padStart(8)} │ ${row.encrypt.mean.toFixed(1).padStart(11)} ${row.wrap.mean.toFixed(2).padStart(8)} ${row.decrypt.mean.toFixed(1).padStart(11)} │ ` +
            `${row.ipfsPlain.mean.toFixed(0).padStart(13)} ${row.ipfsEnc.mean.toFixed(0).padStart(11)} ${(100 * row.overheadVsPlainIpfs).toFixed(1).padStart(7)}%`);
    }

    const outDir = path.resolve(__dirname, 'test-results/revision');
    fs.mkdirSync(outDir, { recursive: true });
    const outPath = path.join(outDir, `encryption-${Date.now()}.json`);
    fs.writeFileSync(outPath, JSON.stringify({
        generatedAt: new Date().toISOString(), node: process.version, platform: `${process.platform} ${process.arch}`,
        cpu: os.cpus()[0]?.model, ipfs: { replicas: URLS.length, urls: URLS, note: 'replicas on one host' },
        method: { warmup: WARMUP, iterations: ITER, iterationsLarge: ITER_LARGE, timer: 'performance.now()',
                  file: 'random bytes; first 32 bytes changed per iteration (no IPFS deduplication)' },
        rows
    }, null, 2));
    fs.rmSync(tmp, { recursive: true, force: true });
    console.log(`\nSaved ${outPath}`);
})().catch(e => { console.error(e); process.exit(1); });
