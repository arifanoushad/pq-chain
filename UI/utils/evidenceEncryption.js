// UI/utils/evidenceEncryption.js
//
// WP3 (R1.3, R2.W3): evidence files are encrypted before they reach IPFS.
//
//   file ──AES-256-GCM (random 256-bit data key, AAD = evidenceId)──► ciphertext ──► IPFS (ciphertextCid)
//   data key ──ML-KEM-768 seal (utils/pqSeal.js)──► one wrapped key per recipient (PoliceOrg, CourtOrg)
//   envelope = { ciphertextCid, plaintextSha256, iv, tag, wrappedKeys, ... } ──► IPFS (envelopeCid)
//
// The envelope CID is the `cid` recorded in the signed evidence metadata, so
// content addressing binds ciphertext, wrapped keys and plaintext hash to the
// signature. Retrieval: fetch envelope → fetch ciphertext (IPFS checks its
// CID) → unwrap the data key with the recipient's ML-KEM secret key →
// decrypt (GCM tag) → check SHA-256 of the plaintext.
//
// Files are processed as streams, so large evidence is never held in memory.
//
// Recipient keys: node scripts/generate-recipient-keys.js writes public keys
// to UI/config/evidence-recipients.json and each organisation's secret key to
// UI/data/keys/<Org>.kem.json (both generated locally, not committed).

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream');

const pqSeal = require('./pqSeal');

const ENVELOPE_VERSION = 1;
const FILE_ALG = 'AES-256-GCM';
const RECIPIENTS_FILE = path.resolve(__dirname, '../config/evidence-recipients.json');
const KEYS_DIR = path.resolve(__dirname, '../data/keys');

const aadFor = evidenceId => Buffer.from(`PQ-Chain evidence v${ENVELOPE_VERSION}|${evidenceId}`);
const keyAad = (evidenceId, recipient) => `${evidenceId}|${recipient}`;

/** { PoliceOrg: { kemPublicKey }, CourtOrg: { kemPublicKey } } */
function loadRecipients(file = RECIPIENTS_FILE) {
    if (!fs.existsSync(file)) {
        throw new Error(`Recipient keys not found (${file}); run node scripts/generate-recipient-keys.js`);
    }
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function loadSecretKey(org, dir = KEYS_DIR) {
    return JSON.parse(fs.readFileSync(path.join(dir, `${org}.kem.json`), 'utf8')).kemSecretKey;
}

/** Counts and hashes bytes flowing through a stream. */
function meter() {
    const hash = crypto.createHash('sha256');
    let size = 0;
    const t = new Transform({
        transform(chunk, _enc, cb) { hash.update(chunk); size += chunk.length; cb(null, chunk); }
    });
    t.result = () => ({ sha256: hash.digest('hex'), size });
    return t;
}

/**
 * Encrypt a file. @returns envelope fields except ciphertextCid.
 * @param {string} inPath
 * @param {string} outPath - ciphertext output
 * @param {Object} o
 * @param {string} o.evidenceId
 * @param {Object} o.recipients - { name: { kemPublicKey } }
 */
async function encryptFile(inPath, outPath, { evidenceId, recipients }) {
    if (!evidenceId) throw new Error('encryptFile: evidenceId required');
    const names = Object.keys(recipients || {});
    if (!names.length) throw new Error('encryptFile: at least one recipient required');

    const dataKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
    cipher.setAAD(aadFor(evidenceId));
    const plain = meter();
    await pipeline(fs.createReadStream(inPath), plain, cipher, fs.createWriteStream(outPath));
    const { sha256, size } = plain.result();

    const wrappedKeys = [];
    for (const name of names) {
        wrappedKeys.push({
            recipient: name,
            sealed: await pqSeal.seal(recipients[name].kemPublicKey, dataKey, keyAad(evidenceId, name), 'evidence-data-key')
        });
    }
    dataKey.fill(0);

    return {
        version: ENVELOPE_VERSION,
        evidenceId,
        alg: FILE_ALG,
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        plaintextSha256: sha256,
        plaintextSize: size,
        wrappedKeys
    };
}

/**
 * Decrypt a ciphertext file for one recipient; verifies the GCM tag and the
 * plaintext SHA-256 recorded in the envelope. Removes outPath on failure.
 */
async function decryptFile(inPath, outPath, envelope, { recipient, kemSecretKey }) {
    if (!envelope || envelope.version !== ENVELOPE_VERSION || envelope.alg !== FILE_ALG) {
        throw new Error('decryptFile: unsupported envelope');
    }
    const wrapped = (envelope.wrappedKeys || []).find(w => w.recipient === recipient);
    if (!wrapped) throw new Error(`decryptFile: no wrapped key for ${recipient}`);
    const dataKey = await pqSeal.open(kemSecretKey, wrapped.sealed, keyAad(envelope.evidenceId, recipient), 'evidence-data-key');

    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(aadFor(envelope.evidenceId));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plain = meter();
    try {
        await pipeline(fs.createReadStream(inPath), decipher, plain, fs.createWriteStream(outPath));
    } catch (e) {
        fs.rmSync(outPath, { force: true });
        throw new Error('decryptFile: authentication failed (ciphertext, tag or evidence ID altered)');
    } finally {
        dataKey.fill(0);
    }
    const { sha256, size } = plain.result();
    if (sha256 !== envelope.plaintextSha256 || size !== envelope.plaintextSize) {
        fs.rmSync(outPath, { force: true });
        throw new Error('decryptFile: plaintext hash does not match the envelope');
    }
    return { sha256, size };
}

// ─── IPFS ────────────────────────────────────────────────────────────────

async function addAndPin(ipfsClients, content) {
    let cid = null;
    for (const client of ipfsClients) {
        const body = typeof content === 'function' ? content() : content;
        const added = await client.add(body, { cidVersion: 1, rawLeaves: true });
        const c = added.cid.toString();
        if (cid && c !== cid) throw new Error(`IPFS nodes returned different CIDs (${cid} vs ${c})`);
        cid = c;
        await client.pin.add(c);
    }
    return cid;
}

/**
 * Encrypt a file and store ciphertext + envelope on every given IPFS node.
 * @returns {Promise<{envelopeCid, ciphertextCid, envelope, timings}>}
 */
async function storeEncryptedEvidence(ipfsClients, inPath, { evidenceId, recipients, workDir }) {
    const clients = Array.isArray(ipfsClients) ? ipfsClients : [ipfsClients];
    const encPath = path.join(workDir || path.dirname(inPath), `${path.basename(inPath)}.${crypto.randomBytes(4).toString('hex')}.enc`);
    const t0 = Date.now();
    try {
        const header = await encryptFile(inPath, encPath, { evidenceId, recipients });
        const tEnc = Date.now();
        const ciphertextCid = await addAndPin(clients, () => fs.createReadStream(encPath));
        const envelope = { ...header, ciphertextCid, ciphertextSize: fs.statSync(encPath).size };
        const envelopeCid = await addAndPin(clients, Buffer.from(JSON.stringify(envelope)));
        const tEnd = Date.now();
        return { envelopeCid, ciphertextCid, envelope, timings: { encryptMs: tEnc - t0, ipfsMs: tEnd - tEnc, totalMs: tEnd - t0 } };
    } finally {
        fs.rmSync(encPath, { force: true });
    }
}

async function catToFile(client, cid, outPath) {
    await pipeline((async function* () { for await (const chunk of client.cat(cid)) yield chunk; })(), fs.createWriteStream(outPath));
}

async function fetchEnvelope(client, envelopeCid) {
    const chunks = [];
    for await (const chunk of client.cat(envelopeCid)) chunks.push(chunk);
    const envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (envelope.version !== ENVELOPE_VERSION || !envelope.ciphertextCid) {
        throw new Error('fetchEnvelope: not an encrypted-evidence envelope');
    }
    return envelope;
}

/**
 * Fetch and decrypt evidence for one recipient into outPath.
 * @returns {Promise<{envelope, sha256, size}>}
 */
async function retrieveDecryptedEvidence(client, envelopeCid, outPath, { recipient, kemSecretKey, evidenceId }) {
    const envelope = await fetchEnvelope(client, envelopeCid);
    if (evidenceId && envelope.evidenceId !== evidenceId) {
        throw new Error('retrieveDecryptedEvidence: envelope belongs to a different evidence ID');
    }
    const encPath = `${outPath}.${crypto.randomBytes(4).toString('hex')}.enc`;
    try {
        await catToFile(client, envelope.ciphertextCid, encPath);
        const r = await decryptFile(encPath, outPath, envelope, { recipient, kemSecretKey });
        return { envelope, ...r };
    } finally {
        fs.rmSync(encPath, { force: true });
    }
}

module.exports = {
    ENVELOPE_VERSION, FILE_ALG, RECIPIENTS_FILE, KEYS_DIR,
    loadRecipients, loadSecretKey,
    encryptFile, decryptFile,
    storeEncryptedEvidence, fetchEnvelope, retrieveDecryptedEvidence
};
