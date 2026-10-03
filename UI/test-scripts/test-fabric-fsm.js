// UI/test-scripts/test-fabric-fsm.js
//
// R1.2 / R2.W1: the Fabric-side 2PC state machine (evidence-transfer.go) on
// the live Fabric 2.4.8 network (Network/startNetwork.sh +
// deploy-evidence-ccaas.sh), through FabricTransferClient in real mode.
// Every write is endorsed by both organisations and committed via the
// 3-orderer Raft service.
//
// Checks: NONE -> PREPARED -> COMMITTED and PREPARED -> ABORTED; idempotent
// prepare / commit / abort; terminal states irreversible; evidence lock while
// PREPARED and released on commit / abort; input validation.
//
// Run:  cd UI && FABRIC_MODE=real node test-scripts/test-fabric-fsm.js

const crypto = require('crypto');
const FabricTransferClient = require('../utils/fabricTransferClient');

let passed = 0, failed = 0;
function expect(cond, label, detail) {
    if (cond) { console.log('   ✅', label); passed++; }
    else      { console.log('   ❌', label); if (detail) console.log('      ', detail); failed++; }
}
async function rejects(promise, pattern) {
    try { await promise; return { ok: false, msg: 'no error' }; }
    catch (e) { return { ok: pattern.test(e.message), msg: e.message.slice(0, 200) }; }
}

async function main() {
    const fabric = new FabricTransferClient({ mode: 'real' });
    // Setup transactions (user + evidence) are not part of the 2PC client API.
    const { contract } = await fabric._connect();
    const run = Date.now().toString(36);
    const address = crypto.randomBytes(20).toString('hex');
    const evidenceId = `FSM-${run}`;
    const signer = crypto.randomBytes(20).toString('hex');
    const h = crypto.randomBytes(32).toString('hex');
    const bundleHash = '0x' + crypto.randomBytes(32).toString('hex');
    const txA = `tx-${run}-A`, txB = `tx-${run}-B`, txC = `tx-${run}-C`;
    const prep = (txId, over = {}) => fabric.prepare({
        txId, evidenceId, metadataHash: h, signerSet: [signer], bundleHash, algorithm: 'DILITHIUM3', ...over
    });
    const status = async txId => (await fabric.getStatus(txId)).result;

    console.log('\n[0] Setup: register uploader and submit evidence');
    await contract.submitTransaction('RegisterUser', 'FSM tester', 'fsm@test', 'pk-' + run, address, new Date().toISOString());
    await contract.submitTransaction('SubmitEvidence', evidenceId, 'FSM test', 'bafytest' + run, 'application/octet-stream',
        address, 'sig-' + run, crypto.randomBytes(32).toString('hex'));
    expect(true, `evidence ${evidenceId} submitted`);

    console.log('\n[1] NONE -> PREPARED');
    expect(await status(txA) === 'NONE', 'unknown txId has status NONE');
    const p1 = await prep(txA);
    expect(p1.result === 'PREPARED' && await status(txA) === 'PREPARED', 'PrepareTransfer -> PREPARED');
    const rec = (await fabric.getTransfer(txA)).result;
    expect(rec.metadataHash === h && rec.bundleHash === bundleHash && rec.signerSet?.[0] === signer &&
           rec.evidenceId === evidenceId && rec.targetChain === 'besu',
        'record stores metadataHash, bundleHash, signerSet, evidenceId, targetChain');

    console.log('\n[2] Idempotent prepare and evidence lock');
    expect((await prep(txA)).result === 'PREPARED', 're-prepare with identical arguments is idempotent');
    let r = await rejects(prep(txA, { bundleHash: '0x' + '11'.repeat(32) }), /already exists/);
    expect(r.ok, 're-prepare with different arguments rejected', r.msg);
    r = await rejects(prep(txB), /locked/);
    expect(r.ok, 'second transfer of the same evidence rejected while PREPARED (lock)', r.msg);

    console.log('\n[3] PREPARED -> COMMITTED (terminal)');
    expect((await fabric.commit(txA)).result === 'COMMITTED' && await status(txA) === 'COMMITTED', 'CommitTransfer -> COMMITTED');
    expect((await fabric.commit(txA)).result === 'COMMITTED', 'repeat commit is idempotent');
    r = await rejects(fabric.abort(txA, 'late abort'), /COMMITTED; cannot abort/);
    expect(r.ok, 'abort after commit rejected', r.msg);

    console.log('\n[4] Lock released; PREPARED -> ABORTED (terminal)');
    expect((await prep(txB)).result === 'PREPARED', 'new transfer of the same evidence allowed after commit');
    expect((await fabric.abort(txB, 'test abort')).result === 'ABORTED' && await status(txB) === 'ABORTED', 'AbortTransfer -> ABORTED');
    expect((await fabric.abort(txB, 'again')).result === 'ABORTED', 'repeat abort is idempotent');
    r = await rejects(fabric.commit(txB), /ABORTED; cannot commit/);
    expect(r.ok, 'commit after abort rejected', r.msg);
    expect((await prep(txC)).result === 'PREPARED', 'lock released after abort');
    await fabric.abort(txC, 'cleanup');

    console.log('\n[5] Input validation');
    r = await rejects(fabric.commit(`tx-${run}-unknown`), /no transfer/);
    expect(r.ok, 'commit of unknown txId rejected', r.msg);
    r = await rejects(prep(`tx-${run}-D`, { evidenceId: `NOPE-${run}` }), /does not exist/);
    expect(r.ok, 'prepare for non-existent evidence rejected', r.msg);
    r = await rejects(prep(`tx-${run}-E`, { signerSet: [] }), /signerSet must be non-empty/);
    expect(r.ok, 'empty signerSet rejected', r.msg);
    r = await rejects(prep(`tx-${run}-F`, { algorithm: 'RSA' }), /unsupported algorithm/);
    expect(r.ok, 'unsupported algorithm rejected', r.msg);

    await fabric.close();
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
