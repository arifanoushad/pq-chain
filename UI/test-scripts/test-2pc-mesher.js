// UI/test-scripts/test-2pc-mesher.js
//
// End-to-end tests for the 2PC cross-chain coordinator (Besu live,
// Fabric in whatever mode is set via FABRIC_MODE).
//
// Prereqs:
//   1. Besu running with EvidenceReceiverV2 deployed
//      (UI/artifacts-v2/EvidenceReceiverV2.json must exist)
//   2. Chunk 1 files installed (thresholdMultiSignature.js, userManager.js)
//   3. IPFS API reachable for the bundle store (default http://127.0.0.1:5001),
//      or BUNDLE_IPFS_URLS="" for archive-only (see utils/bundleStore.js)
//
// Run:
//   cd UI
//   export V2_CONTRACT_ADDRESS=$(node -e "console.log(require('./artifacts-v2/EvidenceReceiverV2.json').address)")
//   node test-scripts/test-2pc-mesher.js
//
// Five tests:
//   [1] Happy path: real multi-sig bundle + prepare + commit on Besu (+ stub on Fabric)
//   [2] Abort injection: force besu.prepare to fail, verify coordinated rollback
//   [3] Timeout path: force besu.prepare to hang past 2s, verify timeout + rollback
//   [4] Idempotency: retry a committed txId, verify no state change
//   [5] Recovery: simulate coordinator crash after prepare, run recoverPendingTransfers()
// With FABRIC_MODE=real, evidence is first submitted on Fabric (setup, see
// fabric-fixtures.js) and the Fabric chaincode state is checked after each test.

const crypto = require('crypto');

const CompleteCrossChainMesher = require('../utils/completeCrossChainMesher');
const BesuTransferClient       = require('../utils/besuTransferClient');
const FabricTransferClient     = require('../utils/fabricTransferClient');
const ThresholdMultiSignature  = require('../utils/thresholdMultiSignature');
const UserManager              = require('../utils/userManager');
const fabricFixtures           = require('./fabric-fixtures');
const { auditTransfer }        = require('../utils/bundleAuditor');

let passed = 0, failed = 0;
function ok(label) { console.log('   ✅', label); passed++; }
function bad(label, detail) {
    console.log('   ❌', label);
    if (detail) console.log('      ', detail);
    failed++;
}

async function makeBundle({ algorithm = 'DILITHIUM3', t = 3, n = 5 } = {}) {
    const um  = new UserManager();
    const tms = new ThresholdMultiSignature(um);

    const members = [];
    for (let i = 0; i < n; i++) {
        const kp = await um.generateKeyPair(algorithm);
        members.push({ address: kp.address, publicKey: kp.publicKey, privateKey: kp.privateKey });
    }

    const metadata = {
        evidenceId: 'CASE-' + Date.now(),
        cid: 'QmXyZ' + Math.random().toString(36).slice(2, 10),
        algorithm, timestamp: Date.now()
    };
    const metadataHash = crypto.createHash('sha256').update(JSON.stringify(metadata)).digest('hex');
    if (fabricFixtures.isReal()) await fabricFixtures.submitEvidence(metadata.evidenceId, metadataHash);

    const partials = [];
    for (let i = 0; i < t; i++) {
        const p = await tms.generatePartialSignature({
            privateKey: members[i].privateKey,
            publicKey:  members[i].publicKey,
            memberAddress: members[i].address,
            evidenceHash: metadataHash,
            algorithm
        });
        partials.push(p);
    }
    const bundle = await tms.combinePartialSignatures(partials, t);

    return {
        evidenceId: metadata.evidenceId,
        metadataHash,
        multiSigBundle: bundle,
        algorithm,
        signerSet: members.slice(0, t).map(m => m.address),
        members, metadata
    };
}

async function main() {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║  2PC CROSS-CHAIN MESHER — END-TO-END TESTS               ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log(`  FABRIC_MODE = ${process.env.FABRIC_MODE || 'stub (default)'}`);

    // ─── Test 1: Happy path ─────────────────────────────────────────────
    console.log('\n[1] Happy path: prepare both → commit both');
    {
        const mesher = new CompleteCrossChainMesher();
        const req = await makeBundle();
        const res = await mesher.transfer(req);
        if (res.success && res.outcome === 'COMMITTED') {
            ok(`COMMITTED in ${res.phaseTimings.total} ms (prepare=${res.phaseTimings.prepare}ms, finalize=${res.phaseTimings.finalize}ms)`);
        } else {
            bad('expected COMMITTED', JSON.stringify(res));
        }

        // Verify Besu side truly recorded COMMITTED
        const status = await mesher.besu.getStatus(res.txId);
        if (status.statusName === 'COMMITTED') ok(`Besu state = ${status.statusName}`);
        else                                    bad('Besu state should be COMMITTED', status.statusName);
        await expectFabricStatus(mesher, res.txId, 'COMMITTED');

        // Real Fabric: full auditor check (both chains + bundle store)
        if (fabricFixtures.isReal()) {
            const audit = await auditTransfer({
                txId: res.txId, besu: mesher.besu, fabric: mesher.fabric, store: mesher.bundleStore,
                tms: new ThresholdMultiSignature(new UserManager()),
                registry: req.members.map(m => ({ address: m.address, publicKey: m.publicKey }))
            });
            if (audit.ok) ok(`auditor: all ${audit.checks.length} checks pass (bundle from ${audit.source})`);
            else          bad('auditor failed', audit.checks.filter(c => !c.ok).map(c => `${c.name}: ${c.detail}`).join('; '));
        }
    }

    // ─── Test 2: Abort injection ────────────────────────────────────────
    console.log('\n[2] Abort injection: besu.prepare fails → both sides abort');
    {
        const mesher = new CompleteCrossChainMesher();
        // Patch besu.prepare to throw deterministically
        const orig = mesher.besu.prepare.bind(mesher.besu);
        mesher.besu.prepare = async () => { throw new Error('INJECTED besu.prepare failure'); };

        const req = await makeBundle();
        const res = await mesher.transfer(req);

        // Restore
        mesher.besu.prepare = orig;

        if (!res.success && res.outcome === 'ABORTED') {
            ok(`ABORTED as expected: ${res.reason?.substring(0, 80)}`);
        } else {
            bad('expected ABORTED', JSON.stringify(res));
        }
        await expectFabricStatus(mesher, res.txId, 'ABORTED');
    }

    // ─── Test 3: Timeout path ───────────────────────────────────────────
    // Window: 2 s prepare timeout + up to 2 s grace for the hanging prepare
    // + one abort round on the real chains.
    console.log('\n[3] Timeout: besu.prepare hangs past 2s → abort');
    {
        const mesher = new CompleteCrossChainMesher({ config: { prepareTimeoutMs: 2_000 } });
        const orig = mesher.besu.prepare.bind(mesher.besu);
        mesher.besu.prepare = () => new Promise(() => { /* never resolves */ });

        const req = await makeBundle();
        const t0 = Date.now();
        const res = await mesher.transfer(req);
        const elapsed = Date.now() - t0;

        mesher.besu.prepare = orig;

        if (!res.success && res.outcome === 'ABORTED' && elapsed >= 2_000 && elapsed < 10_000) {
            ok(`timed out and aborted in ${elapsed} ms (within 2–10 s window)`);
        } else {
            bad(`expected timeout+ABORTED`, `elapsed=${elapsed}ms outcome=${res.outcome}`);
        }
        await expectFabricStatus(mesher, res.txId, 'ABORTED');
    }

    // ─── Test 4: Idempotency ────────────────────────────────────────────
    console.log('\n[4] Idempotency: retry commit on already-committed txId');
    {
        const mesher = new CompleteCrossChainMesher();
        const req = await makeBundle();
        const first = await mesher.transfer(req);
        if (first.outcome !== 'COMMITTED') {
            bad('first transfer should commit', first.outcome);
        } else {
            // Replay commit directly
            try {
                const replay = await mesher.besu.commit(first.txId);
                if (replay.success) ok(`replay commit succeeded (idempotent)`);
                else                 bad('replay commit should have succeeded');
            } catch (e) {
                bad('replay commit threw', e.message);
            }
            if (fabricFixtures.isReal()) {
                try {
                    const f = await mesher.fabric.commit(first.txId);
                    if (f.result === 'COMMITTED') ok('Fabric replay commit succeeded (idempotent)');
                    else                          bad('Fabric replay commit should return COMMITTED', f.result);
                } catch (e) {
                    bad('Fabric replay commit threw', e.message);
                }
            }
        }
    }

    // ─── Test 5: Recovery ───────────────────────────────────────────────
    console.log('\n[5] Recovery: crash after prepare, run recoverPendingTransfers()');
    {
        const mesher = new CompleteCrossChainMesher();
        const req = await makeBundle();

        // Drive prepare only, then "crash" by not calling commit/abort.
        const txId = mesher.computeTxId({ evidenceId: req.evidenceId, metadataHash: req.metadataHash });
        mesher._log({ type: 'TXN_STARTED', txId, evidenceId: req.evidenceId, metadataHash: req.metadataHash });

        const bundleHash = ThresholdMultiSignature.hashBundleBytes(
            ThresholdMultiSignature.encodeBundle(req.multiSigBundle));

        try {
            await mesher.besu.prepare({
                txId,
                evidenceId: req.evidenceId,
                metadataHash: req.metadataHash,
                algorithm: req.algorithm,
                bundleHash
            });
            mesher._log({ type: 'PREPARE_OK', txId, chain: 'besu' });
        } catch (e) {
            bad('setup prepare failed', e.message);
            return;
        }

        // "crash" — no commit/abort logged
        // Now run recovery
        const recov = await mesher.recoverPendingTransfers({ commitWhenBothPrepared: true });
        const matching = recov.resolved.find(r => r.txId === txId);

        if (matching && matching.ok) {
            const finalStatus = await mesher.besu.getStatus(txId);
            if (finalStatus.statusName === 'COMMITTED' || finalStatus.statusName === 'ABORTED') {
                ok(`recovery resolved to ${finalStatus.statusName} (action=${matching.action})`);
            } else {
                bad('recovery did not reach terminal state', finalStatus.statusName);
            }
        } else {
            bad('recovery did not resolve the pending txn', JSON.stringify(recov));
        }
    }

    // ─── Summary ────────────────────────────────────────────────────────
    console.log('\n╔══════════════════════════════════════════════════════════╗');
    console.log(`║  RESULT: ${passed}/${passed+failed} tests passed${' '.repeat(Math.max(0, 36 - String(passed+failed).length))}║`);
    console.log('╚══════════════════════════════════════════════════════════╝');

    await fabricFixtures.close();
    process.exit(failed ? 1 : 0);
}

// Real Fabric only: the chaincode's state must match the coordinator outcome.
async function expectFabricStatus(mesher, txId, expected) {
    if (!fabricFixtures.isReal()) return;
    const r = await mesher.fabric.getStatus(txId);
    if (r.result === expected) ok(`Fabric state = ${r.result}`);
    else                       bad(`Fabric state should be ${expected}`, r.result);
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
