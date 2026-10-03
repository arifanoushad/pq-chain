// UI/test-scripts/test-multi-sig-real.js
//
// End-to-end test and micro-benchmark for the real ML-DSA multi-signature.
//
// What this proves:
//   1. A (t,n) = (3,5) police committee can sign, aggregate, and verify
//      using REAL ML-DSA-65. No SHA-256+XOR. No setTimeout delays.
//   2. Any t members can sign; fewer than t cannot produce a valid bundle.
//   3. A bundle with a tampered signature is rejected.
//   4. A bundle with a non-committee signer is rejected.
//   5. Bundle sizes and verification times are measured, not simulated.
//   6. A bundle carrying a substituted public key under a registered
//      address is rejected (embedded key bound to the registered signer).
//
// Run with:  node UI/test-scripts/test-multi-sig-real.js
//
// Expected output: all seven tests PASS and a table with real latencies
// and bundle sizes per algorithm, suitable for the paper.

const ThresholdMultiSignature = require('../utils/thresholdMultiSignature');
const UserManager = require('../utils/userManager');
const crypto = require('crypto');

async function setupCommittee(um, size, algorithm) {
    const members = [];
    for (let i = 0; i < size; i++) {
        const kp = await um.generateKeyPair(algorithm);
        members.push({
            address: kp.address,
            publicKey: kp.publicKey,
            privateKey: kp.privateKey,
            name: `Officer_${i + 1}`
        });
    }
    return members;
}

function evidenceHashOf(metadata) {
    return crypto.createHash('sha256').update(JSON.stringify(metadata)).digest('hex');
}

async function assertTrue(cond, label) {
    if (cond) { console.log(`   ✅ ${label}`); }
    else      { console.log(`   ❌ ${label}`); process.exitCode = 1; }
}

async function assertFalse(cond, label) {
    return assertTrue(!cond, label);
}

async function runAlgorithm(algorithm) {
    console.log(`\n════════ ${algorithm} ════════`);

    const um = new UserManager();
    const tms = new ThresholdMultiSignature(um);

    const N = 5;                         // committee size
    const T = 3;                         // threshold
    const members = await setupCommittee(um, N, algorithm);
    // Alg. 6 roster P = {(ID_j, pk_j)}: address plus full registered public key
    const registeredCommittee = members.map(m => ({ address: m.address, publicKey: m.publicKey }));

    const metadata = {
        evidenceId: 'CASE-001',
        cid: 'QmXyZ123testCID',
        algorithm,
        timestamp: Date.now(),
        fileSize: 4_200_000_000
    };
    const eHash = evidenceHashOf(metadata);

    // ─── Test 1: t of n members sign and verify successfully ────────────
    console.log('\n[1] Happy path: 3 of 5 members sign, court verifies');
    const signers = members.slice(0, T);

    const signStart = Date.now();
    const partials = [];
    for (const m of signers) {
        const p = await tms.generatePartialSignature({
            privateKey: m.privateKey,
            publicKey:  m.publicKey,
            memberAddress: m.address,
            evidenceHash: eHash,
            algorithm
        });
        partials.push(p);
    }
    const totalSignMs = Date.now() - signStart;

    const bundle = await tms.combinePartialSignatures(partials, T);

    const verifyStart = Date.now();
    const vr = await tms.verifyMultiSignature(bundle, eHash, registeredCommittee);
    const totalVerifyMs = Date.now() - verifyStart;

    await assertTrue(vr.isValid, 'Bundle verifies');
    await assertTrue(vr.validSignatureCount === T, `Exactly ${T} valid partial signatures`);
    await assertTrue(vr.verifiedSigners.length === T, 'All signers recorded');

    // ─── Test 2: fewer than t partials rejected at combine time ─────────
    console.log('\n[2] Too few signers: aggregator rejects');
    try {
        await tms.combinePartialSignatures(partials.slice(0, T - 1), T);
        await assertTrue(false, 'Combine should have thrown for insufficient signers');
    } catch (e) {
        await assertTrue(e.message.includes('need at least'), `Combine threw: "${e.message}"`);
    }

    // ─── Test 3: tampered signature is detected ─────────────────────────
    console.log('\n[3] Tampered signature: court rejects');
    const tamperedBundle = JSON.parse(JSON.stringify(bundle));
    // Flip a hex nibble in the first partial's signature
    const sig = tamperedBundle.partials[0].signature;
    tamperedBundle.partials[0].signature = (sig[0] === '0' ? '1' : '0') + sig.slice(1);
    const vrTampered = await tms.verifyMultiSignature(tamperedBundle, eHash, registeredCommittee);
    await assertFalse(vrTampered.isValid, 'Tampered bundle rejected');
    await assertTrue(
        typeof vrTampered.reason === 'string' && vrTampered.reason.toLowerCase().includes('failed'),
        `Reason reported: "${vrTampered.reason}"`
    );

    // ─── Test 4: mismatched evidence hash is detected ───────────────────
    console.log('\n[4] Wrong evidence hash: court rejects');
    const wrongHash = crypto.createHash('sha256').update('different evidence').digest('hex');
    const vrWrongHash = await tms.verifyMultiSignature(bundle, wrongHash, registeredCommittee);
    await assertFalse(vrWrongHash.isValid, 'Wrong-hash bundle rejected');

    // ─── Test 5: non-committee signer is detected ───────────────────────
    console.log('\n[5] Outsider signer: policy check rejects');
    const outsider = (await setupCommittee(um, 1, algorithm))[0];
    const outsiderPartial = await tms.generatePartialSignature({
        privateKey: outsider.privateKey,
        publicKey:  outsider.publicKey,
        memberAddress: outsider.address,
        evidenceHash: eHash,
        algorithm
    });
    const mixedPartials = [partials[0], partials[1], outsiderPartial];
    const bundleWithOutsider = await tms.combinePartialSignatures(mixedPartials, T);
    const vrOutsider = await tms.verifyMultiSignature(bundleWithOutsider, eHash, registeredCommittee);
    await assertFalse(vrOutsider.isValid, 'Bundle with outsider rejected');

    // ─── Test 6: duplicate signer is detected ───────────────────────────
    console.log('\n[6] Duplicate signer: aggregator rejects');
    try {
        await tms.combinePartialSignatures([partials[0], partials[0], partials[1]], T);
        await assertTrue(false, 'Combine should have thrown on duplicates');
    } catch (e) {
        await assertTrue(e.message.includes('distinct'), `Combine threw: "${e.message}"`);
    }

    // ─── Test 7: serialize / deserialize round-trip ─────────────────────
    console.log('\n[7] Serialize ↔ deserialize round-trip');
    const serialized = tms.serializeBundle(bundle);
    const restored = tms.deserializeBundle(serialized);
    const vrRestored = await tms.verifyMultiSignature(restored, eHash, registeredCommittee);
    await assertTrue(vrRestored.isValid, 'Round-tripped bundle verifies');

    // ─── Test 8: substituted public key is detected ─────────────────────
    // An attacker signs with their own key but claims a registered member's
    // address; the embedded key must be that member's registered key.
    console.log('\n[8] Substituted key under a registered address: court rejects');
    const attacker = (await setupCommittee(um, 1, algorithm))[0];
    const victim = partials[0].memberAddress;
    const forgedSig = await um.createSignature(attacker.privateKey, `${eHash}:${victim}`, algorithm);
    const forgedBundle = JSON.parse(JSON.stringify(bundle));
    forgedBundle.partials[0].publicKey = attacker.publicKey;
    forgedBundle.partials[0].signature = forgedSig.signature;
    const vrForged = await tms.verifyMultiSignature(forgedBundle, eHash, registeredCommittee);
    await assertFalse(vrForged.isValid, 'Substituted key rejected');
    await assertTrue(
        typeof vrForged.reason === 'string' && vrForged.reason.includes('not the registered key'),
        `Reason reported: "${vrForged.reason}"`
    );
    // The registered key is authoritative, even if the embedded key hashes
    // to the right address (the 160-bit address check is never sufficient).
    const rotatedRegistry = registeredCommittee.map((m, i) => i ? m : { ...m, publicKey: attacker.publicKey });
    const vrRotated = await tms.verifyMultiSignature(bundle, eHash, rotatedRegistry);
    await assertFalse(vrRotated.isValid, 'Embedded key differing from the registered key rejected');
    const addressOnly = members.map(m => m.address);
    const vrAddrOnly = await tms.verifyMultiSignature(bundle, eHash, addressOnly);
    await assertFalse(vrAddrOnly.isValid, 'Address-only registry (no public keys) rejected');

    // ─── Reporting ──────────────────────────────────────────────────────
    const onChainBytes = Buffer.byteLength(serialized, 'utf8') / 2; // hex → bytes
    console.log('\n────── Real measurements ──────');
    console.log(`  Partial sign time (t=${T} signers, sequential): ${totalSignMs} ms (~${(totalSignMs / T).toFixed(2)} ms/signer)`);
    console.log(`  Bundle verify time (t=${T} signatures):         ${totalVerifyMs} ms`);
    console.log(`  Bundle size (on-chain bytes):                    ${onChainBytes} B`);
    console.log(`  Per-partial crypto time avg:                     ${vr.performance.avgPerPartialMs.toFixed(2)} ms`);

    return {
        algorithm,
        threshold: T,
        totalMembers: N,
        totalSignMs,
        totalVerifyMs,
        perSignerSignMs: totalSignMs / T,
        bundleSizeBytes: onChainBytes,
        avgPartialVerifyMs: vr.performance.avgPerPartialMs
    };
}

async function main() {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║  REAL ML-DSA MULTI-SIGNATURE — END-TO-END TEST & BENCHMARK  ║');
    console.log('╚══════════════════════════════════════════════════════════╝');

    const summary = [];
    for (const algo of ['ECC', 'DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5']) {
        try {
            const r = await runAlgorithm(algo);
            summary.push(r);
        } catch (e) {
            console.log(`\n❌ ${algo} suite failed: ${e.message}`);
            console.log(e.stack);
            process.exitCode = 1;
        }
    }

    console.log('\n╔═════════════════════════════════════════════════════════════╗');
    console.log('║  SUMMARY — real numbers you can cite in the paper           ║');
    console.log('╚═════════════════════════════════════════════════════════════╝');
    console.log('Algorithm     │ t/n │ Sign tot │ /signer │ Verify │ Bundle   ');
    console.log('──────────────┼─────┼──────────┼─────────┼────────┼──────────');
    for (const r of summary) {
        console.log(
            `${r.algorithm.padEnd(13)} │ ${r.threshold}/${r.totalMembers} │ ${String(r.totalSignMs + ' ms').padStart(8)} │ ${(r.perSignerSignMs.toFixed(2) + ' ms').padStart(7)} │ ${String(r.totalVerifyMs + ' ms').padStart(6)} │ ${String(r.bundleSizeBytes + ' B').padStart(8)}`
        );
    }
    console.log('\n✅ Multi-signature test complete.\n');
}

if (require.main === module) {
    main().catch(err => {
        console.error('Fatal:', err);
        process.exit(1);
    });
}

module.exports = { setupCommittee, evidenceHashOf, runAlgorithm };
