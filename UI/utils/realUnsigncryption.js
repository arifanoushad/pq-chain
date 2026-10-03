// utils/realUnsigncryption.js
//
// Real signature verification for the court side.
//
// ─── What changed vs the previous version ───────────────────────────────
// The previous verifyThresholdSignature() looped over public keys while
// keeping the SAME signature fixed.  That is not how multi-signature
// verification works: each member's signature must be checked against
// THAT member's public key.  The previous loop would only ever return
// validCount === 1 in a real deployment (the signature only verifies
// under its true signer's public key), masking the bug when the benchmark
// happened to use a single signer.
//
// The corrected implementation takes (partial_sig, public_key) PAIRS and
// delegates to ThresholdMultiSignature.verifyMultiSignature, which is the
// real cryptographic primitive.  The single-signature verifySignature()
// entry point is unchanged and still supports real ML-DSA + ECC via
// @noble/post-quantum and the elliptic library.

const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// Real Dilithium modules (loaded dynamically, same pattern as userManager.js)
let ml_dsa44, ml_dsa65, ml_dsa87;

async function loadDilithiumModules() {
    if (!ml_dsa44) {
        const noble = await import('@noble/post-quantum/ml-dsa.js');
        ml_dsa44 = noble.ml_dsa44;
        ml_dsa65 = noble.ml_dsa65;
        ml_dsa87 = noble.ml_dsa87;
        console.log('✅ Loaded real Dilithium for unsigncryption');
    }
}

class RealUnsigncryption {

    // ─── Single-signature verify (unchanged) ────────────────────────────
    async verifySignature(signatureHex, originalData, publicKey, algorithm) {
        const message = Buffer.from(originalData);
        const signature = Buffer.from(signatureHex, 'hex');

        switch (algorithm) {
            case 'ECC':
                return this.verifyECCSignature(publicKey, message, signature);

            case 'DILITHIUM2':
                await loadDilithiumModules();
                return ml_dsa44.verify(signature, message, Buffer.from(publicKey, 'base64'));

            case 'DILITHIUM3':
                await loadDilithiumModules();
                return ml_dsa65.verify(signature, message, Buffer.from(publicKey, 'base64'));

            case 'DILITHIUM5':
                await loadDilithiumModules();
                return ml_dsa87.verify(signature, message, Buffer.from(publicKey, 'base64'));

            default:
                throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
    }

    verifyECCSignature(publicKeyHex, message, signature) {
        try {
            const keyPair = ec.keyFromPublic(publicKeyHex, 'hex');
            const dataHash = crypto.createHash('sha256').update(message).digest('hex');
            return keyPair.verify(dataHash, signature);
        } catch (error) {
            console.error('ECC verification error:', error.message);
            return false;
        }
    }

    // ─── Multi-signature bundle verify (FIXED) ──────────────────────────
    //
    // Accepts the bundle produced by ThresholdMultiSignature.combinePartialSignatures()
    // and verifies each partial against its OWN public key.
    //
    // @param {Object} bundle               - multi-signature bundle
    // @param {string} expectedEvidenceHash
    // @param {Array<string>} registeredCommittee  - addresses authorized for this committee
    // @returns {Promise<boolean>} true iff ≥ threshold valid distinct partials
    async verifyBundle(bundle, expectedEvidenceHash, registeredCommittee) {
        // Lazy-require to avoid circular imports during tests.
        const ThresholdMultiSignature = require('./thresholdMultiSignature');
        const tms = new ThresholdMultiSignature();
        const result = await tms.verifyMultiSignature(bundle, expectedEvidenceHash, registeredCommittee);
        return result.isValid;
    }

    // ─── DEPRECATED: previous verifyThresholdSignature ──────────────────
    //
    // Kept as a named stub that throws, so any legacy call site surfaces
    // immediately instead of silently returning a misleading result.
    async verifyThresholdSignature(/* combinedSignature, evidenceHash, publicKeys, algorithm, threshold */) {
        throw new Error(
            'verifyThresholdSignature is deprecated. ' +
            'Use verifyBundle(bundle, expectedEvidenceHash, registeredCommittee) instead. ' +
            'The bundle must be produced by ThresholdMultiSignature.combinePartialSignatures().'
        );
    }

    generateEvidenceHash(evidenceData) {
        return crypto.createHash('sha256').update(JSON.stringify(evidenceData)).digest('hex');
    }
}

module.exports = RealUnsigncryption;
