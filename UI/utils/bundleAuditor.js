// UI/utils/bundleAuditor.js
//
// Auditor-side check of a cross-chain transfer's multi-signature bundle
// (JISA R1.4).  Only bundleHash is on-chain; the bundle is fetched from
// the bundle store and checked against it.
//
// Steps:
//   1. Besu.getTransfer(txId): status must be COMMITTED
//   2. Fabric.GetTransfer(txId): COMMITTED and same evidenceId, metadataHash,
//      bundleHash, algorithm as Besu
//   3. Fetch bundle bytes by bundleHash (IPFS, then archive); the store only
//      returns bytes whose SHA-256 equals bundleHash
//   4. Decode; evidenceHash / algorithm must match the on-chain record
//   5. Each embedded public key must hash to its member address, so the
//      bundle is self-contained even if registry keys are rotated or lost
//   6. Signers must equal Fabric's on-chain signerSet
//   7. VerifyBundle (ML-DSA / ECC per partial) against the committee registry;
//      embedded keys must equal the full registered keys

const ThresholdMultiSignature = require('./thresholdMultiSignature');

const hex = v => String(v ?? '').toLowerCase().replace(/^0x/, '');

/**
 * @param {Object}   p
 * @param {string}   p.txId
 * @param {Object}   p.besu      - BesuTransferClient (getTransfer)
 * @param {Object}   p.fabric    - FabricTransferClient (getTransfer)
 * @param {Object}   p.store     - BundleStore (get)
 * @param {Object}   p.tms       - ThresholdMultiSignature instance
 * @param {Object[]} p.registry  - registered committee as { address, publicKey }
 * @returns {Promise<Object>} { ok, checks: [{ name, ok, detail }], signers, bundleSize, source }
 */
async function auditTransfer({ txId, besu, fabric, store, tms, registry }) {
    const checks = [];
    const check = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail }); return !!ok; };
    const result = () => ({ ok: checks.every(c => c.ok), checks });

    // 1. Besu record
    const b = await besu.getTransfer(txId);
    if (!check('besu status COMMITTED', b.statusName === 'COMMITTED', b.statusName)) return result();

    // 2. Fabric record and cross-chain agreement
    let f = null;
    try { f = (await fabric.getTransfer(txId)).result; } catch (e) { f = null; }
    if (!check('fabric record present', f && typeof f === 'object', f ? undefined : 'no Fabric record')) return result();
    check('fabric status COMMITTED', f.status === 'COMMITTED', f.status);
    for (const field of ['evidenceId', 'metadataHash', 'bundleHash', 'algorithm']) {
        const same = field.endsWith('Hash') ? hex(f[field]) === hex(b[field]) : f[field] === b[field];
        check(`fabric/besu ${field} match`, same, same ? undefined : `fabric=${f[field]} besu=${b[field]}`);
    }

    // 3. Fetch bundle by on-chain hash
    let fetched;
    try {
        fetched = await store.get(b.bundleHash);
    } catch (e) {
        check('bundle retrievable and matches bundleHash', false, e.message);
        return result();
    }
    check('bundle retrievable and matches bundleHash', true, `${fetched.bytes.length} B from ${fetched.source}`);

    // 4. Decode and bind to the on-chain record
    let bundle;
    try {
        bundle = ThresholdMultiSignature.decodeBundle(fetched.bytes);
    } catch (e) {
        check('bundle decodes', false, e.message);
        return result();
    }
    check('bundle evidenceHash = on-chain metadataHash', bundle.evidenceHash === hex(b.metadataHash));
    check('bundle algorithm = on-chain algorithm', bundle.algorithm === b.algorithm);

    // 5. Embedded public keys belong to the stated members
    const um = tms.userManager;
    const badKeys = bundle.partials.filter(p => um.getAddressFromPublicKey(p.publicKey) !== p.memberAddress);
    check('embedded public keys match member addresses', badKeys.length === 0,
        badKeys.length ? badKeys.map(p => p.memberAddress).join(', ') : undefined);

    // 6. Signers = Fabric signerSet
    const signers = bundle.partials.map(p => p.memberAddress);
    const fabricSet = Array.isArray(f.signerSet) ? f.signerSet : [];
    check('bundle signers = fabric signerSet',
        signers.length === fabricSet.length && signers.every((a, i) => a === fabricSet[i]));

    // 7. Cryptographic verification against the registry
    const vr = await tms.verifyMultiSignature(bundle, hex(b.metadataHash), registry);
    check('VerifyBundle', vr.isValid, vr.reason);

    return { ...result(), signers, bundleSize: fetched.bytes.length, source: fetched.source };
}

module.exports = { auditTransfer };
