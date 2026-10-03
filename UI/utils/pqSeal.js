// UI/utils/pqSeal.js
//
// Post-quantum public-key sealing: ML-KEM-768 (FIPS 203) key encapsulation,
// HKDF-SHA256 key derivation and AES-256-GCM authenticated encryption.
// seal() encrypts a message so that only the holder of the ML-KEM secret key
// can open() it; the associated data (aad) is authenticated, not encrypted.
//
// Used for Shamir share custody (each share sealed to its member) and, in
// WP3, for wrapping per-evidence file keys to the Police / Court recipients.

const crypto = require('crypto');

const ALG = 'ML-KEM-768+HKDF-SHA256+AES-256-GCM';

let kemPromise = null;
function kem() {
    if (!kemPromise) kemPromise = import('@noble/post-quantum/ml-kem.js').then(m => m.ml_kem768);
    return kemPromise;
}

const b64 = u8 => Buffer.from(u8).toString('base64');

function deriveKey(sharedSecret, kemCiphertext, info) {
    // Salt binds the key to this encapsulation; info separates uses.
    return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(sharedSecret), Buffer.from(kemCiphertext),
        Buffer.from(`PQ-Chain seal v1|${info}`), 32));
}

/** @returns {Promise<{publicKey: string, secretKey: string}>} base64 keys */
async function generateKeyPair() {
    const k = await kem();
    const { publicKey, secretKey } = k.keygen();
    return { publicKey: b64(publicKey), secretKey: b64(secretKey) };
}

/**
 * @param {string} publicKey  - base64 ML-KEM-768 public key of the recipient
 * @param {Buffer|string} plaintext
 * @param {string} aad        - authenticated context (e.g. committee | member | index)
 * @param {string} info       - purpose label for key derivation
 */
async function seal(publicKey, plaintext, aad, info) {
    const k = await kem();
    const { cipherText, sharedSecret } = k.encapsulate(Buffer.from(publicKey, 'base64'));
    const key = deriveKey(sharedSecret, cipherText, info);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    return {
        alg: ALG,
        kemCiphertext: b64(cipherText),
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        ciphertext: ciphertext.toString('base64')
    };
}

/** Throws if the key, aad or any sealed field is wrong. @returns {Promise<Buffer>} */
async function open(secretKey, sealed, aad, info) {
    if (!sealed || sealed.alg !== ALG) throw new Error('pqSeal.open: unsupported or missing algorithm');
    const k = await kem();
    const kemCiphertext = Buffer.from(sealed.kemCiphertext, 'base64');
    // ML-KEM decapsulation with a wrong key returns an unrelated secret
    // (implicit rejection); the GCM tag check below then fails.
    const sharedSecret = k.decapsulate(kemCiphertext, Buffer.from(secretKey, 'base64'));
    const key = deriveKey(sharedSecret, kemCiphertext, info);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    try {
        return Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, 'base64')), decipher.final()]);
    } catch (e) {
        throw new Error('pqSeal.open: authentication failed (wrong key or tampered data)');
    }
}

module.exports = { ALG, generateKeyPair, seal, open };
