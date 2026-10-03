// UI/test-scripts/test-bundle-store.js
//
// JISA R1.4: offline tests for the canonical bundle encoding, the durable
// bundle store, the store-before-prepare coordinator phase and the auditor.
// No network is needed: IPFS and Besu are in-memory fakes, Fabric is the
// real FabricTransferClient in stub mode with a temporary journal.
//
// Run:  cd UI && node test-scripts/test-bundle-store.js

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const UserManager              = require('../utils/userManager');
const ThresholdMultiSignature  = require('../utils/thresholdMultiSignature');
const BundleStore              = require('../utils/bundleStore');
const CompleteCrossChainMesher = require('../utils/completeCrossChainMesher');
const FabricTransferClient     = require('../utils/fabricTransferClient');
const { auditTransfer }        = require('../utils/bundleAuditor');

const { encodeBundle, decodeBundle, hashBundleBytes, BUNDLE_ALGORITHMS, BUNDLE_HEADER_BYTES } = ThresholdMultiSignature;

let passed = 0, failed = 0;
function expect(cond, label, detail) {
    if (cond) { console.log('   ✅', label); passed++; }
    else      { console.log('   ❌', label); if (detail) console.log('      ', detail); failed++; }
}
async function throws(fn, pattern) {
    try { await fn(); return false; } catch (e) { return pattern ? pattern.test(e.message) : true; }
}
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pqchain-bundle-'));

// ─── Fakes ───────────────────────────────────────────────────────────────

function fakeIpfs({ fail = false } = {}) {
    const blocks = new Map();
    const pins = new Set();
    return {
        blocks, pins, putOptions: [],
        block: {
            async put(buf, opts) {
                if (fail) throw new Error('node down');
                this.parent.putOptions.push(opts);
                const cid = BundleStore.cidFromBundleHash(sha256(buf));
                blocks.set(cid, Buffer.from(buf));
                return { toString: () => cid };
            },
            async get(cid) {
                const b = blocks.get(String(cid));
                if (!b) throw new Error('block not found');
                return b;
            }
        },
        pin: { async add(cid) { pins.add(String(cid)); } }
    };
}
function withParent(ipfs) { ipfs.block.parent = ipfs; return ipfs; }

function fakeBesu() {
    const records = new Map();
    const set = (txId, status) => {
        const r = records.get(txId);
        if (!r) throw new Error('no transfer');
        r.statusName = status;
        return { success: true };
    };
    return {
        records,
        async prepare({ txId, evidenceId, metadataHash, algorithm, bundleHash }) {
            if (records.has(txId)) throw new Error('transfer exists');
            records.set(txId, { evidenceId, metadataHash: '0x' + metadataHash, bundleHash, algorithm, statusName: 'PREPARED' });
            return { success: true };
        },
        async commit(txId) { return set(txId, 'COMMITTED'); },
        async abort(txId)  { return set(txId, 'ABORTED'); },
        async getStatus(txId) { return { statusName: records.get(txId)?.statusName || 'NONE' }; },
        async getTransfer(txId) { return { ...(records.get(txId) || { statusName: 'NONE' }) }; }
    };
}

// ─── Bundle factory ──────────────────────────────────────────────────────

async function makeBundle(um, tms, algorithm, t, n = t + 2) {
    const members = [];
    for (let i = 0; i < n; i++) members.push(await um.generateKeyPair(algorithm));
    const metadataHash = crypto.randomBytes(32).toString('hex');
    const partials = [];
    for (let i = 0; i < t; i++) {
        partials.push(await tms.generatePartialSignature({
            privateKey: members[i].privateKey, publicKey: members[i].publicKey,
            memberAddress: members[i].address, evidenceHash: metadataHash, algorithm
        }));
    }
    const bundle = await tms.combinePartialSignatures(partials, t);
    return { bundle, members, metadataHash, registry: members.map(m => ({ address: m.address, publicKey: m.publicKey })) };
}

async function main() {
    const log = console.log;
    const quiet = async fn => { console.log = () => {}; try { return await fn(); } finally { console.log = log; } };

    const um  = await quiet(() => new UserManager());
    const tms = new ThresholdMultiSignature(um);

    // ─── [1] Canonical encoding ──────────────────────────────────────────
    console.log('\n[1] Canonical binary encoding');
    for (const algo of BUNDLE_ALGORITHMS) {
        const { bundle, metadataHash, registry } = await quiet(() => makeBundle(um, tms, algo.name, 3));
        const bytes = encodeBundle(bundle);
        const sigTotal = bundle.partials.reduce((s, p) => s + p.signature.length / 2, 0);
        const expectedSize = BUNDLE_HEADER_BYTES + 3 * (20 + algo.publicKeyBytes + 2) + sigTotal;
        const decoded = decodeBundle(bytes);
        const vr = await quiet(() => tms.verifyMultiSignature(decoded, metadataHash, registry));
        expect(bytes.length === expectedSize, `${algo.name}: size ${bytes.length} B = header + t·(addr + pk + len + sig)`);
        expect(vr.isValid, `${algo.name}: decoded bundle verifies`, vr.reason);
        expect(encodeBundle(decoded).equals(bytes), `${algo.name}: decode → encode is byte-identical`);
        const noise = { ...bundle, timestamp: 'x', performance: { combineTime: 999 } };
        expect(encodeBundle(noise).equals(bytes), `${algo.name}: timestamp/performance fields do not affect the bytes`);
    }

    const { bundle: b65, metadataHash: h65, registry: reg65, members: mem65 } =
        await quiet(() => makeBundle(um, tms, 'DILITHIUM3', 3));
    const bytes65 = encodeBundle(b65);

    console.log('\n[2] Strict decoding / encoding');
    expect(await throws(() => decodeBundle(bytes65.subarray(0, bytes65.length - 1)), /truncated/), 'truncated bundle rejected');
    expect(await throws(() => decodeBundle(Buffer.concat([bytes65, Buffer.from([0])])), /trailing/), 'trailing bytes rejected');
    const badVersion = Buffer.from(bytes65); badVersion[0] = 9;
    expect(await throws(() => decodeBundle(badVersion), /version/), 'unknown version rejected');
    const badAlgo = Buffer.from(bytes65); badAlgo[1] = 7;
    expect(await throws(() => decodeBundle(badAlgo), /algorithm/), 'unknown algorithm id rejected');
    const zeroT = Buffer.from(bytes65); zeroT[2] = 0;
    expect(await throws(() => decodeBundle(zeroT), /no partials/), 't = 0 rejected');
    const prefixed = { ...b65, partials: b65.partials.map((p, i) => i ? p : { ...p, memberAddress: '0x' + p.memberAddress }) };
    expect(await throws(() => encodeBundle(prefixed), /memberAddress/), 'non-canonical (0x-prefixed) address rejected by encoder');
    const shortSig = { ...b65, partials: b65.partials.map((p, i) => i ? p : { ...p, signature: p.signature.slice(2) }) };
    expect(await throws(() => encodeBundle(shortSig), /signature/), 'wrong-length ML-DSA signature rejected by encoder');

    // ─── [3] CID derivation ──────────────────────────────────────────────
    console.log('\n[3] CID derived from bundleHash');
    const hash65 = hashBundleBytes(bytes65);
    const cid = BundleStore.cidFromBundleHash(hash65);
    expect(/^bafkrei[a-z2-7]{52}$/.test(cid), `CIDv1 raw/sha2-256 form (${cid.slice(0, 16)}…)`);
    try {
        const { CID }    = require('multiformats/cid');
        const { sha256: mh } = require('multiformats/hashes/sha2');
        const raw        = require('multiformats/codecs/raw');
        const ref = CID.create(1, raw.code, await mh.digest(bytes65)).toString();
        expect(ref === cid, 'matches the multiformats reference implementation', `${ref} vs ${cid}`);
    } catch (e) {
        console.log('   ⚠️  multiformats cross-check skipped:', e.message);
    }

    // ─── [4] Store: archive + IPFS replicas ──────────────────────────────
    console.log('\n[4] Bundle store');
    {
        const dir = tmpDir();
        const archiveOnly = new BundleStore({ ipfsUrls: [], archiveDir: dir });
        const put = await archiveOnly.put(bytes65);
        expect(put.bundleHash === hash65 && put.cid === cid, 'put returns bundleHash and derived CID');
        const got = await archiveOnly.get(hash65);
        expect(got.bytes.equals(bytes65) && got.source === 'archive', 'archive-only get returns identical bytes');
        const f = path.join(dir, hash65.slice(2) + '.bin');
        const tampered = Buffer.from(bytes65); tampered[100] ^= 1;
        fs.writeFileSync(f, tampered);
        expect(await throws(() => archiveOnly.get(hash65), /hash mismatch/), 'tampered archive copy rejected');
        expect(await throws(() => archiveOnly.get('0x' + '11'.repeat(32)), /not found/), 'unknown bundleHash → not found');
    }
    {
        const a = withParent(fakeIpfs()), b = withParent(fakeIpfs());
        const store = new BundleStore({ ipfsClients: [a, b], archiveDir: tmpDir() });
        const put = await store.put(bytes65);
        expect(put.pinnedOn.length === 2 && a.pins.has(cid) && b.pins.has(cid), 'pinned on all configured IPFS nodes');
        expect(a.putOptions[0]?.searchParams?.['cid-codec'] === 'raw' && a.putOptions[0]?.searchParams?.mhtype === 'sha2-256',
            'block.put requests raw codec + sha2-256');
        a.blocks.set(cid, Buffer.from('corrupted'));
        const got = await store.get(hash65);
        expect(got.bytes.equals(bytes65) && got.source === 'ipfs#1', 'corrupted replica skipped, healthy replica used');
    }
    {
        const store = new BundleStore({ ipfsClients: [withParent(fakeIpfs()), withParent(fakeIpfs({ fail: true }))], minReplicas: 2, archiveDir: tmpDir() });
        expect(await throws(() => store.put(bytes65), /pinned on 1\/2/), 'put fails when fewer than minReplicas nodes pin');
    }

    // ─── [5] Coordinator: store before prepare ───────────────────────────
    console.log('\n[5] Coordinator stores the bundle before prepare');
    const work = tmpDir();
    const newMesher = (store, besu = fakeBesu()) => {
        const fabric = new FabricTransferClient({ mode: 'stub', journalPath: path.join(work, `fabric-${Math.random()}.jsonl`) });
        return new CompleteCrossChainMesher({
            besu, fabric, bundleStore: store,
            logPath: path.join(work, `mesher-${Math.random()}.jsonl`),
            config: { retryBackoffMs: 1 }
        });
    };
    const request = { evidenceId: 'CASE-R14', metadataHash: h65, multiSigBundle: b65, algorithm: 'DILITHIUM3',
                      signerSet: b65.partials.map(p => p.memberAddress) };

    const ipfs = withParent(fakeIpfs());
    const store = new BundleStore({ ipfsClients: [ipfs], archiveDir: tmpDir() });
    const order = [];
    const besu = fakeBesu();
    const origPut = store.put.bind(store), origPrep = besu.prepare;
    store.put = async bytes => { order.push('store'); return origPut(bytes); };
    besu.prepare = async args => { order.push('besu.prepare'); return origPrep(args); };
    const mesher = newMesher(store, besu);
    const origFab = mesher.fabric.prepare.bind(mesher.fabric);
    mesher.fabric.prepare = async args => { order.push('fabric.prepare'); return origFab(args); };

    const res = await quiet(() => mesher.transfer(request));
    expect(res.outcome === 'COMMITTED', 'transfer COMMITTED', JSON.stringify(res).slice(0, 200));
    expect(order[0] === 'store' && order.length === 3, `store happens before both prepares (${order.join(' → ')})`);
    expect(typeof res.phaseTimings.store === 'number' && res.phaseTimings.total >= res.phaseTimings.store,
        `phaseTimings.store reported separately (${res.phaseTimings.store} ms)`);
    expect(besu.records.get(res.txId).bundleHash === hash65, 'Besu anchors SHA-256 of the canonical bytes');
    expect(ipfs.pins.has(cid), 'bundle pinned on IPFS');

    {
        const failing = { put: async () => { throw new Error('IPFS unreachable'); } };
        const besu2 = fakeBesu();
        const m2 = newMesher(failing, besu2);
        const r2 = await quiet(() => m2.transfer(request));
        const journal = fs.readFileSync(m2.fabric.journalPath, 'utf8');
        expect(r2.outcome === 'ABORTED' && /bundle-store-failure/.test(r2.reason), 'store failure → ABORTED before prepare');
        expect(besu2.records.size === 0 && !journal.includes('PrepareTransfer'), 'no chain touched when store fails');
        const rec = await quiet(() => m2.recoverPendingTransfers());
        expect(rec.pending === 0, 'store-failed transfer is terminal in the coordinator log (no recovery needed)');
    }
    {
        // A prepare that times out but lands later must still be aborted.
        const besuLate = fakeBesu();
        const mLate = newMesher(new BundleStore({ ipfsUrls: [], archiveDir: tmpDir() }), besuLate);
        mLate.config.prepareTimeoutMs = 200;
        mLate.config.abortGraceMs = 1_000;
        const realPrep = besuLate.prepare;
        besuLate.prepare = args => new Promise(r => setTimeout(() => r(realPrep(args)), 500));
        mLate.fabric.prepare = async () => { throw new Error('INJECTED fabric failure'); };
        const rLate = await quiet(() => mLate.transfer(request));
        const st = (await besuLate.getStatus(rLate.txId)).statusName;
        expect(rLate.outcome === 'ABORTED' && st === 'ABORTED', `late-landing prepare aborted (Besu = ${st})`);

        // Still unresolved after the grace period → not terminal, recovery aborts it later.
        const besuHang = fakeBesu();
        const mHang = newMesher(new BundleStore({ ipfsUrls: [], archiveDir: tmpDir() }), besuHang);
        mHang.config.prepareTimeoutMs = 100;
        mHang.config.abortGraceMs = 100;
        besuHang.prepare = () => new Promise(() => {});
        mHang.fabric.prepare = async () => { throw new Error('INJECTED fabric failure'); };
        await quiet(() => mHang.transfer(request));
        const logged = fs.readFileSync(mHang.logPath, 'utf8');
        expect(/ABORT_PENDING/.test(logged) && !/TXN_ABORTED/.test(logged), 'unresolved prepare logged ABORT_PENDING (not terminal)');
    }
    {
        const m3 = newMesher(new BundleStore({ ipfsUrls: [], archiveDir: tmpDir() }));
        const reordered = { ...request, signerSet: [...request.signerSet].reverse() };
        expect(await throws(() => m3.transfer(reordered), /signerSet/), 'signerSet must equal the bundle signers');
    }

    // ─── [6] Auditor ─────────────────────────────────────────────────────
    console.log('\n[6] Auditor');
    const audit = (over = {}) => quiet(() => auditTransfer({
        txId: res.txId, besu, fabric: mesher.fabric, store, tms, registry: reg65, ...over
    }));
    const failedChecks = r => r.checks.filter(c => !c.ok).map(c => c.name).join(', ');

    const good = await audit();
    expect(good.ok, `honest transfer passes all ${good.checks.length} checks`, failedChecks(good));

    const r1 = await audit({ registry: reg65.slice(1) });
    expect(!r1.ok && /VerifyBundle/.test(failedChecks(r1)), 'signer outside the registry → rejected');

    const fabricWith = patch => ({ getTransfer: async id => {
        const r = await mesher.fabric.getTransfer(id);
        return { ...r, result: { ...r.result, ...patch } };
    } });
    const r2 = await audit({ fabric: fabricWith({ bundleHash: '0x' + '22'.repeat(32) }) });
    expect(!r2.ok && /bundleHash match/.test(failedChecks(r2)), 'Fabric/Besu bundleHash disagreement → rejected');
    const r3 = await audit({ fabric: fabricWith({ signerSet: [...request.signerSet].reverse() }) });
    expect(!r3.ok && /signerSet/.test(failedChecks(r3)), 'bundle signers ≠ Fabric signerSet → rejected');

    // Substitute a signer's key: attacker key + attacker signature under a
    // registered address.  Both VerifyBundle and the auditor must reject it.
    {
        const attacker = await quiet(() => um.generateKeyPair('DILITHIUM3'));
        const victim = b65.partials[0].memberAddress;
        const sig = await quiet(() => um.createSignature(attacker.privateKey, `${h65}:${victim}`, 'DILITHIUM3'));
        const forged = { ...b65, partials: b65.partials.map((p, i) => i ? p : { ...p, publicKey: attacker.publicKey, signature: sig.signature }) };
        const besuF = fakeBesu();
        const mF = newMesher(store, besuF);
        const rF = await quiet(() => mF.transfer({ ...request, multiSigBundle: forged }));
        const vrOnly = await quiet(() => tms.verifyMultiSignature(forged, h65, reg65));
        const aF = await quiet(() => auditTransfer({ txId: rF.txId, besu: besuF, fabric: mF.fabric, store, tms, registry: reg65 }));
        expect(!vrOnly.isValid && /not the registered key/.test(vrOnly.reason), 'VerifyBundle rejects a substituted key', vrOnly.reason);
        expect(!aF.ok && /public keys match/.test(failedChecks(aF)), 'auditor rejects substituted key via address = H(pk)');
    }

    ipfs.blocks.set(cid, Buffer.from('corrupted'));
    fs.writeFileSync(path.join(store.archiveDir, hash65.slice(2) + '.bin'), Buffer.from('also corrupted'));
    const r4 = await audit();
    expect(!r4.ok && /retrievable/.test(failedChecks(r4)), 'all copies corrupted → bundle check fails (hash anchor detects it)');
    const f4 = r4.checks.filter(c => c.name.startsWith('fabric')).every(c => c.ok);
    expect(f4, 'Fabric record (incl. signerSet) still readable when the bundle is lost');

    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
