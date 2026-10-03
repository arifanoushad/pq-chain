// utils/thresholdMultiSignature.js
//
// Real (t,n) MULTI-SIGNATURE using ML-DSA (Dilithium) or ECC per-signer.
//
// This is the honest post-quantum primitive that backs the paper's
// multi-party authorization claim. It replaced an earlier simulated scheme
// (SHA-256 + XOR + setTimeout; removed from the repository) with genuine
// cryptography.
//
// ─── Design ─────────────────────────────────────────────────────────────
// 1. Each committee member independently signs  (evidenceHash || memberAddress)
//    with their own ML-DSA (or ECC) private key, using UserManager.createSignature.
//    Binding the member's address into the signed message prevents
//    rogue-key / signature-reattribution attacks across members.
//
// 2. "Combining" is bundling: the t partial signatures are concatenated with
//    their corresponding (publicKey, memberAddress) into a verifiable bundle.
//    This is NOT a cryptographic aggregation (no Lagrange, no BLS). It is
//    a multi-signature, which is the correct name for what we are building.
//
// 3. Verification iterates over each partial signature and performs a REAL
//    ML-DSA verify against its own public key. A bundle is valid iff:
//      (a) the bundle contains ≥ t partial signatures,
//      (b) each partial signature cryptographically verifies,
//      (c) all signers are distinct,
//      (d) every signer's address is in the registered committee.
//
// 4. The committee's Shamir secret (from committeeManager.js) continues to
//    enforce (t,n) authorization at the application layer — an attacker
//    controlling < t shares cannot assemble a bundle that will be accepted
//    by the aggregator. The Shamir layer is orthogonal to, and does not
//    affect, the ML-DSA signature primitive.
//
// ─── Security ───────────────────────────────────────────────────────────
// Unforgeability inherits directly from ML-DSA EUF-CMA (NIST FIPS 204).
// Producing any valid partial signature requires the corresponding ML-DSA
// private key. Producing a valid bundle of t partials requires t private
// keys belonging to t distinct registered committee members.
//
// ─── Honest naming ──────────────────────────────────────────────────────
// This is a MULTI-SIGNATURE, not a threshold signature in the Shamir /
// FROST / Ringtail sense. A true threshold signature would produce a
// single aggregate signature verifiable against a single aggregate public
// key. We do not do that. We bundle t independent signatures, which is
// the cleanest honest primitive we can build without a threshold-Dilithium
// library. The paper must reflect this (see the audit document).

const crypto      = require('crypto');
const UserManager = require('./userManager');

// ─── Canonical binary bundle encoding (JISA R1.4) ─────────────────────────
// The encoded bytes are what is stored off-chain (IPFS + archive) and what
// bundleHash = SHA-256(bytes) commits to on both chains.  Public keys are
// embedded so a bundle stays verifiable on its own even if registry keys
// are later rotated or lost.
//
// Layout (integers big-endian):
//   u8   encoding version (= 1)
//   u8   algorithm id (0 ECC, 1 ML-DSA-44, 2 ML-DSA-65, 3 ML-DSA-87)
//   u8   t (number of partials; equals the threshold)
//   32 B evidence hash (SHA-256 of the metadata)
//   t ×  { 20 B member address | public key (fixed length per algorithm) |
//          u16 signature length | signature }
const BUNDLE_ENCODING_VERSION = 1;
const BUNDLE_ALGORITHMS = [
    // publicKeyEncoding = how UserManager represents the key as a string
    { name: 'ECC',        publicKeyBytes: 65,   signatureBytes: null, publicKeyEncoding: 'hex'    },
    { name: 'DILITHIUM2', publicKeyBytes: 1312, signatureBytes: 2420, publicKeyEncoding: 'base64' },
    { name: 'DILITHIUM3', publicKeyBytes: 1952, signatureBytes: 3309, publicKeyEncoding: 'base64' },
    { name: 'DILITHIUM5', publicKeyBytes: 2592, signatureBytes: 4627, publicKeyEncoding: 'base64' }
];
const BUNDLE_HEADER_BYTES = 3 + 32;
const ADDRESS_BYTES = 20;

function encodeBundle(bundle) {
    const algoId = BUNDLE_ALGORITHMS.findIndex(a => a.name === bundle.algorithm);
    if (algoId < 0) throw new Error(`encodeBundle: unsupported algorithm ${bundle.algorithm}`);
    const algo = BUNDLE_ALGORITHMS[algoId];
    const partials = bundle.partials || [];
    if (partials.length < 1 || partials.length > 255 || partials.length !== bundle.threshold) {
        throw new Error('encodeBundle: need 1..255 partials and partials.length === threshold');
    }
    if (!/^[0-9a-f]{64}$/.test(bundle.evidenceHash)) {
        throw new Error('encodeBundle: evidenceHash must be 64 lowercase hex chars');
    }

    const parts = [
        Buffer.from([BUNDLE_ENCODING_VERSION, algoId, partials.length]),
        Buffer.from(bundle.evidenceHash, 'hex')
    ];
    for (const p of partials) {
        // Exact string forms are required: the signed message contains the
        // address string, so any normalisation would break verification.
        if (!/^[0-9a-f]{40}$/.test(p.memberAddress)) {
            throw new Error(`encodeBundle: memberAddress must be 40 lowercase hex chars (${p.memberAddress})`);
        }
        const pk  = Buffer.from(p.publicKey, algo.publicKeyEncoding);
        const sig = Buffer.from(p.signature, 'hex');
        if (pk.length !== algo.publicKeyBytes || pk.toString(algo.publicKeyEncoding) !== p.publicKey) {
            throw new Error(`encodeBundle: malformed ${algo.name} public key for ${p.memberAddress}`);
        }
        if (sig.length === 0 || sig.length > 0xffff || sig.toString('hex') !== p.signature ||
            (algo.signatureBytes && sig.length !== algo.signatureBytes)) {
            throw new Error(`encodeBundle: malformed ${algo.name} signature for ${p.memberAddress}`);
        }
        const sigLen = Buffer.alloc(2);
        sigLen.writeUInt16BE(sig.length);
        parts.push(Buffer.from(p.memberAddress, 'hex'), pk, sigLen, sig);
    }
    return Buffer.concat(parts);
}

function decodeBundle(bytes) {
    const buf = Buffer.from(bytes);
    let off = 0;
    const take = n => {
        if (off + n > buf.length) throw new Error('decodeBundle: truncated bundle');
        const out = buf.subarray(off, off + n);
        off += n;
        return out;
    };

    const [version, algoId, t] = take(3);
    if (version !== BUNDLE_ENCODING_VERSION) throw new Error(`decodeBundle: unsupported version ${version}`);
    const algo = BUNDLE_ALGORITHMS[algoId];
    if (!algo) throw new Error(`decodeBundle: unknown algorithm id ${algoId}`);
    if (t < 1) throw new Error('decodeBundle: bundle has no partials');
    const evidenceHash = take(32).toString('hex');

    const partials = [];
    for (let i = 0; i < t; i++) {
        const memberAddress = take(ADDRESS_BYTES).toString('hex');
        const publicKey = take(algo.publicKeyBytes).toString(algo.publicKeyEncoding);
        const sigLen = take(2).readUInt16BE();
        if (sigLen === 0 || (algo.signatureBytes && sigLen !== algo.signatureBytes)) {
            throw new Error(`decodeBundle: bad signature length ${sigLen} for ${algo.name}`);
        }
        partials.push({ signature: take(sigLen).toString('hex'), publicKey, memberAddress });
    }
    if (off !== buf.length) throw new Error('decodeBundle: trailing bytes after bundle');

    return {
        type: 'multi-signature',
        schemeVersion: 1,
        partials,
        threshold: t,
        evidenceHash,
        algorithm: algo.name,
        implementation: 'real'
    };
}

/** bundleHash as anchored on Fabric and Besu: '0x' + SHA-256 of the canonical bytes. */
function hashBundleBytes(bytes) {
    return '0x' + crypto.createHash('sha256').update(bytes).digest('hex');
}

class ThresholdMultiSignature {
    constructor(userManager) {
        // Allow dependency injection for testing; otherwise create one.
        this.userManager = userManager || new UserManager();
    }

    /**
     * A committee member produces their partial signature on the evidence
     * hash using their own ML-DSA (or ECC) private key.
     *
     * @param {Object} params
     * @param {string} params.privateKey     - base64 (Dilithium) or hex (ECC)
     * @param {string} params.publicKey      - base64 (Dilithium) or hex (ECC)
     * @param {string} params.memberAddress  - member's blockchain address
     * @param {string} params.evidenceHash   - hex-encoded 32-byte SHA-256 of metadata
     * @param {string} [params.algorithm]    - 'ECC' | 'DILITHIUM2' | 'DILITHIUM3' | 'DILITHIUM5'
     * @returns {Promise<Object>} partial signature object
     */
    async generatePartialSignature({ privateKey, publicKey, memberAddress, evidenceHash, algorithm = 'DILITHIUM3' }) {
        if (!privateKey || !publicKey || !memberAddress || !evidenceHash) {
            throw new Error('generatePartialSignature: missing required field');
        }

        const startTime = Date.now();

        // Bind signer identity into the signed message to prevent
        // signature-reattribution attacks.
        const messageToSign = `${evidenceHash}:${memberAddress}`;

        const sigResult = await this.userManager.createSignature(
            privateKey,
            messageToSign,
            algorithm
        );

        const generationTime = Date.now() - startTime;

        return {
            signature: sigResult.signature,         // hex string
            publicKey: publicKey,                   // passed through for verification
            memberAddress: memberAddress,
            evidenceHash: evidenceHash,
            algorithm: algorithm,
            timestamp: new Date().toISOString(),
            performance: {
                generationTime: generationTime,
                signatureSize: sigResult.signatureSize
            },
            implementation: 'real'
        };
    }

    /**
     * Bundle t partial signatures into a multi-signature bundle.
     * This is a concatenation, not a cryptographic operation.
     *
     * @param {Array}  partialSignatures  - array of partial signature objects
     * @param {number} threshold          - required number of valid partials
     * @returns {Promise<Object>} multi-signature bundle
     */
    async combinePartialSignatures(partialSignatures, threshold) {
        const startTime = Date.now();

        if (!Array.isArray(partialSignatures)) {
            throw new Error('combinePartialSignatures: partialSignatures must be an array');
        }
        if (!Number.isInteger(threshold) || threshold < 1) {
            throw new Error('combinePartialSignatures: threshold must be a positive integer');
        }
        if (partialSignatures.length < threshold) {
            throw new Error(`combinePartialSignatures: got ${partialSignatures.length} partials, need at least ${threshold}`);
        }

        const evidenceHash = partialSignatures[0].evidenceHash;
        const algorithm = partialSignatures[0].algorithm;

        for (const p of partialSignatures) {
            if (p.evidenceHash !== evidenceHash) {
                throw new Error('combinePartialSignatures: partials are for different evidence');
            }
            if (p.algorithm !== algorithm) {
                throw new Error('combinePartialSignatures: partials use different algorithms');
            }
        }

        const uniqueSigners = new Set(partialSignatures.map(p => p.memberAddress));
        if (uniqueSigners.size < threshold) {
            throw new Error(`combinePartialSignatures: only ${uniqueSigners.size} distinct signers, need ${threshold}`);
        }

        // Take the first t partials (in practice the aggregator picks any t).
        const selected = partialSignatures.slice(0, threshold);

        const bundleSize = selected.reduce(
            (sum, p) => sum + (p.performance?.signatureSize || 0),
            0
        );

        const combineTime = Date.now() - startTime;

        return {
            type: 'multi-signature',
            schemeVersion: 1,
            partials: selected.map(p => ({
                signature: p.signature,
                publicKey: p.publicKey,
                memberAddress: p.memberAddress
            })),
            threshold: threshold,
            evidenceHash: evidenceHash,
            algorithm: algorithm,
            timestamp: new Date().toISOString(),
            performance: {
                combineTime: combineTime,
                bundleSize: bundleSize  // bytes, sum of partial signature sizes
            },
            implementation: 'real'
        };
    }

    /**
     * Verify a multi-signature bundle.  REAL cryptography: every partial is
     * verified against its own public key using ML-DSA (or ECC).
     *
     * @param {Object}        bundle              - from combinePartialSignatures
     * @param {string}        expectedEvidenceHash
     * @param {Array<Object>} registeredCommittee - authorized members as
     *        { address, publicKey } (Alg. 6 roster P = {(ID_j, pk_j)}).  Each
     *        partial's embedded public key must equal the registered key of its
     *        member (the address-hash check is only an additional check).
     * @returns {Promise<Object>} verification result
     */
    async verifyMultiSignature(bundle, expectedEvidenceHash, registeredCommittee) {
        const startTime = Date.now();

        // ─── Structural checks ─────────────────────────────────────────
        if (!bundle || bundle.type !== 'multi-signature') {
            return { isValid: false, reason: 'Not a multi-signature bundle', performance: { verificationTime: 0 } };
        }
        if (bundle.evidenceHash !== expectedEvidenceHash) {
            return { isValid: false, reason: 'Evidence hash mismatch', performance: { verificationTime: 0 } };
        }
        if (!Array.isArray(bundle.partials) || bundle.partials.length < bundle.threshold) {
            return {
                isValid: false,
                reason: `Bundle has ${bundle.partials?.length || 0} partials, needs ${bundle.threshold}`,
                performance: { verificationTime: 0 }
            };
        }
        if (!Array.isArray(registeredCommittee) || registeredCommittee.length === 0) {
            return { isValid: false, reason: 'No registered committee provided', performance: { verificationTime: 0 } };
        }
        if (registeredCommittee.some(m => !m || typeof m.address !== 'string' || typeof m.publicKey !== 'string' || !m.publicKey)) {
            return {
                isValid: false,
                reason: 'Registered committee must list { address, publicKey } for every member',
                performance: { verificationTime: 0 }
            };
        }

        // ─── Policy checks ─────────────────────────────────────────────
        const committee = new Map(registeredCommittee.map(m => [m.address, m.publicKey]));
        for (const p of bundle.partials) {
            if (!committee.has(p.memberAddress)) {
                return {
                    isValid: false,
                    reason: `Signer ${p.memberAddress} is not in the registered committee`,
                    performance: { verificationTime: Date.now() - startTime }
                };
            }
            // Bind the embedded key to the registered signer (Alg. 6, policy
            // check 3): it must be the full registered key.  The 160-bit
            // address = H(pk) check is an extra consistency check only.
            if (p.publicKey !== committee.get(p.memberAddress) ||
                this.userManager.getAddressFromPublicKey(p.publicKey) !== p.memberAddress) {
                return {
                    isValid: false,
                    reason: `Public key in partial from ${p.memberAddress} is not the registered key of that signer`,
                    performance: { verificationTime: Date.now() - startTime }
                };
            }
        }
        const uniqueSigners = new Set(bundle.partials.map(p => p.memberAddress));
        if (uniqueSigners.size < bundle.threshold) {
            return {
                isValid: false,
                reason: 'Duplicate signers in bundle',
                performance: { verificationTime: Date.now() - startTime }
            };
        }

        // ─── Cryptographic verification ────────────────────────────────
        // Each partial is verified against ITS OWN public key — this is the
        // bug that was present in realUnsigncryption.verifyThresholdSignature,
        // fixed here.
        let validCount = 0;
        const verifiedSigners = [];
        const perPartialTimes = [];

        for (const p of bundle.partials) {
            const messageToVerify = `${bundle.evidenceHash}:${p.memberAddress}`;
            const t0 = Date.now();
            const vr = await this.userManager.verifySignature(
                p.publicKey,
                messageToVerify,
                p.signature,
                bundle.algorithm
            );
            perPartialTimes.push(Date.now() - t0);

            if (vr.isValid) {
                validCount++;
                verifiedSigners.push(p.memberAddress);
            } else {
                return {
                    isValid: false,
                    reason: `Partial signature from ${p.memberAddress} failed cryptographic verification`,
                    validSignatureCount: validCount,
                    performance: { verificationTime: Date.now() - startTime }
                };
            }
        }

        const verificationTime = Date.now() - startTime;
        const avgPerPartial = perPartialTimes.length
            ? perPartialTimes.reduce((a, b) => a + b, 0) / perPartialTimes.length
            : 0;

        return {
            isValid: validCount >= bundle.threshold,
            validSignatureCount: validCount,
            threshold: bundle.threshold,
            verifiedSigners: verifiedSigners,
            algorithm: bundle.algorithm,
            evidenceHash: expectedEvidenceHash,
            performance: {
                verificationTime: verificationTime,
                avgPerPartialMs: avgPerPartial,
                perPartialTimesMs: perPartialTimes
            },
            implementation: 'real'
        };
    }

    /**
     * Legacy JSON serialization (hex of JSON.stringify).  This is the size the
     * original paper reported; the bundle is NOT stored on-chain in this form.
     * The stored and hashed form is encodeBundle() (canonical binary).
     */
    serializeBundle(bundle) {
        return Buffer.from(JSON.stringify(bundle)).toString('hex');
    }

    deserializeBundle(hexBlob) {
        return JSON.parse(Buffer.from(hexBlob, 'hex').toString('utf8'));
    }

    /**
     * Theoretical and practical bundle size, for use in the paper's Table 11.
     */
    getBundleSizeEstimate(algorithm, threshold) {
        // Per-partial = signature + public key + address + JSON overhead (~30 B)
        const sigSizes = { ECC: 72, DILITHIUM2: 2420, DILITHIUM3: 3309, DILITHIUM5: 4627 };
        const pkSizes = { ECC: 64, DILITHIUM2: 1312, DILITHIUM3: 1952, DILITHIUM5: 2592 };
        const sig = sigSizes[algorithm] || sigSizes.DILITHIUM3;
        const pk = pkSizes[algorithm] || pkSizes.DILITHIUM3;
        const perPartial = sig + pk + 40 + 30;   // signature + pk + address + overhead
        return {
            algorithm,
            threshold,
            perPartialBytes: perPartial,
            totalBytes: perPartial * threshold,
            totalKB: (perPartial * threshold) / 1024
        };
    }
}

ThresholdMultiSignature.encodeBundle            = encodeBundle;
ThresholdMultiSignature.decodeBundle            = decodeBundle;
ThresholdMultiSignature.hashBundleBytes         = hashBundleBytes;
ThresholdMultiSignature.BUNDLE_ALGORITHMS       = BUNDLE_ALGORITHMS;
ThresholdMultiSignature.BUNDLE_HEADER_BYTES     = BUNDLE_HEADER_BYTES;
ThresholdMultiSignature.BUNDLE_ENCODING_VERSION = BUNDLE_ENCODING_VERSION;

module.exports = ThresholdMultiSignature;
