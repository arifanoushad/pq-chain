// UI/test-scripts/test-besu-v2.js
//
// End-to-end verification of EvidenceReceiverV2 2PC semantics on a live
// Besu node.  Requires:
//   1. Besu running at BESU_RPC
//   2. EvidenceReceiverV2 deployed (run deploy-v2-contract.js first)
//   3. The deployer's private key in COORDINATOR_KEY (that address is the
//      only one authorised to drive state transitions)
//
// Run from UI/ directory:
//
//   # Pull address from the artifact file saved by deploy-v2-contract.js
//   export V2_CONTRACT_ADDRESS=$(node -e "console.log(require('./artifacts-v2/EvidenceReceiverV2.json').address)")
//   node test-scripts/test-besu-v2.js
//
// Nine behavioural tests are executed; the script exits 0 on all-pass
// and 1 on any failure.

const { Web3 } = require('web3');
const crypto   = require('crypto');

const BESU_RPC          = process.env.BESU_RPC          || 'http://localhost:8545';
const COORDINATOR_KEY   = process.env.COORDINATOR_KEY;
const CONTRACT_ADDRESS  = process.env.V2_CONTRACT_ADDRESS;

if (!COORDINATOR_KEY) {
    console.error('❌ COORDINATOR_KEY env var is required (deployer private key, hex). See README.');
    process.exit(1);
}

if (!CONTRACT_ADDRESS) {
    console.error('❌ V2_CONTRACT_ADDRESS env var is required.');
    console.error('   Run: export V2_CONTRACT_ADDRESS=$(node -e "console.log(require(\'./artifacts-v2/EvidenceReceiverV2.json\').address)")');
    process.exit(1);
}

// Minimal ABI (just what the test exercises)
const V2_ABI = [
    { inputs: [
        { name:'txId',          type:'bytes32' },
        { name:'evidenceId',    type:'string'  },
        { name:'metadataHash',  type:'bytes32' },
        { name:'algorithm',     type:'string'  },
        { name:'bundleHash',    type:'bytes32' }
      ], name:'prepare', outputs:[], stateMutability:'nonpayable', type:'function' },
    { inputs:[{ name:'txId', type:'bytes32' }],
      name:'commit', outputs:[], stateMutability:'nonpayable', type:'function' },
    { inputs:[{ name:'txId', type:'bytes32' }, { name:'reason', type:'string' }],
      name:'abortTransfer', outputs:[], stateMutability:'nonpayable', type:'function' },
    { inputs:[{ name:'txId', type:'bytes32' }],
      name:'getStatus', outputs:[{ name:'', type:'uint8' }], stateMutability:'view', type:'function' },
    { inputs:[{ name:'txId', type:'bytes32' }],
      name:'getTransfer',
      outputs:[
          { name:'evidenceId',   type:'string'  },
          { name:'metadataHash', type:'bytes32' },
          { name:'bundleHash',   type:'bytes32' },
          { name:'algorithm',    type:'string'  },
          { name:'status',       type:'uint8'   },
          { name:'preparedAt',   type:'uint256' },
          { name:'committedAt',  type:'uint256' },
          { name:'abortedAt',    type:'uint256' },
          { name:'abortReason',  type:'string'  }
      ],
      stateMutability:'view', type:'function' },
];

const STATUS = ['NONE','PREPARED','COMMITTED','ABORTED'];

const passes = [];
const fails  = [];
function pass(label)            { console.log('   ✅', label); passes.push(label); }
function fail(label, details)   {
    console.log('   ❌', label);
    if (details) console.log('      ', details);
    fails.push({label, details});
}
function isRevert(err) {
    const m = (err && err.message || '').toLowerCase();
    return m.includes('revert') || m.includes('execution reverted') ||
           m.includes('exists')  || m.includes('prepared');
}

async function main() {
    const web3 = new Web3(BESU_RPC);
    const account = web3.eth.accounts.privateKeyToAccount(COORDINATOR_KEY);
    web3.eth.accounts.wallet.add(account);

    const c = new web3.eth.Contract(V2_ABI, CONTRACT_ADDRESS);

    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║  EvidenceReceiverV2 — 2PC BEHAVIOURAL TEST (live Besu)     ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log(`  RPC:        ${BESU_RPC}`);
    console.log(`  Contract:   ${CONTRACT_ADDRESS}`);
    console.log(`  Caller:     ${account.address}`);

    // ── Test 1: fresh prepare → PREPARED ───────────────────────────────
    console.log('\n[1] fresh prepare → PREPARED');
    const txId = '0x' + crypto.randomBytes(32).toString('hex');
    const evidenceId  = 'CASE-' + Date.now();
    const metadataHash = '0x' + crypto.randomBytes(32).toString('hex');
    const bundleHash   = '0x' + crypto.randomBytes(32).toString('hex');
    try {
        await c.methods.prepare(txId, evidenceId, metadataHash, 'DILITHIUM3', bundleHash)
            .send({ from: account.address, gas: 500000 });
        const status = Number(await c.methods.getStatus(txId).call());
        if (status === 1) pass(`status = ${STATUS[status]}`);
        else              fail('status should be PREPARED', `got ${STATUS[status]}`);
    } catch (e) { fail('prepare threw', e.message); }

    // ── Test 2: duplicate prepare reverts ──────────────────────────────
    console.log('\n[2] duplicate prepare reverts');
    try {
        await c.methods.prepare(txId, evidenceId, metadataHash, 'DILITHIUM3', bundleHash)
            .send({ from: account.address, gas: 500000 });
        fail('duplicate prepare should have reverted');
    } catch (e) {
        if (isRevert(e)) pass(`reverted as expected: "${(e.reason || e.message).substring(0, 80)}"`);
        else             fail('reverted with unexpected error', e.message);
    }

    // ── Test 3: commit → COMMITTED ─────────────────────────────────────
    console.log('\n[3] commit → COMMITTED');
    try {
        await c.methods.commit(txId).send({ from: account.address, gas: 200000 });
        const status = Number(await c.methods.getStatus(txId).call());
        if (status === 2) pass(`status = ${STATUS[status]}`);
        else              fail('status should be COMMITTED', `got ${STATUS[status]}`);
    } catch (e) { fail('commit threw', e.message); }

    // ── Test 4: commit is idempotent ───────────────────────────────────
    console.log('\n[4] second commit is idempotent (no revert)');
    try {
        await c.methods.commit(txId).send({ from: account.address, gas: 200000 });
        pass('repeat commit succeeded');
    } catch (e) { fail('repeat commit threw', e.message); }

    // ── Test 5: abort on COMMITTED reverts ─────────────────────────────
    console.log('\n[5] abort on COMMITTED reverts');
    try {
        await c.methods.abortTransfer(txId, 'too late').send({ from: account.address, gas: 200000 });
        fail('abort on COMMITTED should have reverted');
    } catch (e) {
        if (isRevert(e)) pass(`reverted as expected: "${(e.reason || e.message).substring(0, 80)}"`);
        else             fail('reverted with unexpected error', e.message);
    }

    // ── Test 6: fresh transfer → abort → ABORTED ───────────────────────
    console.log('\n[6] abort path: prepare → abort → ABORTED');
    const txId2 = '0x' + crypto.randomBytes(32).toString('hex');
    try {
        await c.methods.prepare(txId2, evidenceId + '_2', metadataHash, 'DILITHIUM3', bundleHash)
            .send({ from: account.address, gas: 500000 });
        await c.methods.abortTransfer(txId2, 'testing abort')
            .send({ from: account.address, gas: 200000 });
        const status = Number(await c.methods.getStatus(txId2).call());
        if (status === 3) pass(`status = ${STATUS[status]}`);
        else              fail('status should be ABORTED', `got ${STATUS[status]}`);
    } catch (e) { fail('prepare/abort path threw', e.message); }

    // ── Test 7: commit on ABORTED reverts ──────────────────────────────
    console.log('\n[7] commit on ABORTED reverts');
    try {
        await c.methods.commit(txId2).send({ from: account.address, gas: 200000 });
        fail('commit on ABORTED should have reverted');
    } catch (e) {
        if (isRevert(e)) pass(`reverted as expected: "${(e.reason || e.message).substring(0, 80)}"`);
        else             fail('reverted with unexpected error', e.message);
    }

    // ── Test 8: abort is idempotent ────────────────────────────────────
    console.log('\n[8] second abort is idempotent (no revert)');
    try {
        await c.methods.abortTransfer(txId2, 'again').send({ from: account.address, gas: 200000 });
        pass('repeat abort succeeded');
    } catch (e) { fail('repeat abort threw', e.message); }

    // ── Test 9: getTransfer returns full record ────────────────────────
    console.log('\n[9] getTransfer returns the full record');
    try {
        const r = await c.methods.getTransfer(txId).call();
        if (r.evidenceId === evidenceId && Number(r.status) === 2) {
            pass(`evidenceId="${r.evidenceId}" status=${STATUS[Number(r.status)]}`);
        } else {
            fail('getTransfer returned unexpected data', JSON.stringify(r));
        }
    } catch (e) { fail('getTransfer threw', e.message); }

    // Summary
    console.log('\n╔════════════════════════════════════════════════════════╗');
    console.log(`║  RESULT: ${passes.length}/${passes.length+fails.length} tests passed${' '.repeat(Math.max(0, 34 - String(passes.length+fails.length).length))}║`);
    console.log('╚════════════════════════════════════════════════════════╝');

    if (fails.length) {
        console.log('\nFailures:');
        for (const f of fails) {
            console.log(`  • ${f.label}${f.details ? ` — ${f.details}` : ''}`);
        }
        process.exit(1);
    }
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
