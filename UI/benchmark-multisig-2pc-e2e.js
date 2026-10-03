// UI/benchmark-multisig-2pc-e2e.js
//
// Full end-to-end benchmark: real (t,n) ML-DSA multi-signature + real 2PC
// coordinator + live Besu.  Produces the paper's Tables 10 (multi-signature)
// and 11 (end-to-end) in the multi-signer, cross-chain regime.
//
// What it measures, per algorithm, over N iterations:
//   - Upload time: evidence file encrypted (AES-256-GCM, key wrapped with
//     ML-KEM-768 for PoliceOrg + CourtOrg) and stored with its envelope on
//     every IPFS node (WP3); the envelope CID goes into the signed metadata
//   - Sign time (per signer, t signers total, sequential)
//   - Combine time (bundle aggregation)
//   - Store time (bundle pinned on IPFS + archived before prepare; JISA R1.4)
//   - Prepare time (both chains, parallel, coordinator-observed)
//   - Commit time (both chains, parallel)
//   - Verify time (bundle verification on the Besu "court" side)
//   - Total end-to-end time
//   - Bundle size: canonical binary (stored off-chain, hashed on-chain) and
//     the legacy JSON size reported in the original paper
//
// Run:
//   cd UI
//   export V2_CONTRACT_ADDRESS=$(node -e "console.log(require('./artifacts-v2/EvidenceReceiverV2.json').address)")
//   node benchmark-multisig-2pc-e2e.js
//
// Config via environment:
//   BENCH_ITER   - iterations per algorithm (default 20)
//   BENCH_T      - threshold size           (default 3)
//   BENCH_N      - total committee size     (default 5)
//   BENCH_ALGOS  - comma-separated          (default ECC,DILITHIUM2,DILITHIUM3,DILITHIUM5)
//   FABRIC_MODE  - real|stub|off            (required)
//   BENCH_FILE_MB - evidence file size per iteration (default 10)
//   BUNDLE_IPFS_URLS, BUNDLE_MIN_REPLICAS, BUNDLE_ARCHIVE_DIR - see utils/bundleStore.js

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { create } = require('ipfs-http-client');

const CompleteCrossChainMesher = require('./utils/completeCrossChainMesher');
const ThresholdMultiSignature  = require('./utils/thresholdMultiSignature');
const UserManager              = require('./utils/userManager');
const RealUnsigncryption       = require('./utils/realUnsigncryption');
const evidenceEncryption       = require('./utils/evidenceEncryption');
const fabricFixtures           = require('./test-scripts/fabric-fixtures');

const ITER  = Number(process.env.BENCH_ITER)  || 20;
const T     = Number(process.env.BENCH_T)     || 3;
const N     = Number(process.env.BENCH_N)     || 5;
const ALGOS = (process.env.BENCH_ALGOS || 'ECC,DILITHIUM2,DILITHIUM3,DILITHIUM5').split(',');
const FILE_MB = Number(process.env.BENCH_FILE_MB) || 10;
const IPFS_URLS = (process.env.BUNDLE_IPFS_URLS ?? 'http://127.0.0.1:5001').split(',').map(s => s.trim()).filter(Boolean);
const ipfsClients = IPFS_URLS.map(url => create({ url }));
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqchain-e2e-'));
const evidenceFile = path.join(workDir, 'evidence.bin');

function stats(arr) {
    if (!arr.length) return { mean: 0, p95: 0, min: 0, max: 0, std: 0 };
    const sorted = [...arr].sort((a, b) => a - b);
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const p95  = sorted[Math.floor(arr.length * 0.95)] ?? sorted[sorted.length - 1];
    const varsum = arr.map(x => (x - mean) ** 2).reduce((a, b) => a + b, 0);
    const std = Math.sqrt(varsum / arr.length);
    return { mean, p95, min: sorted[0], max: sorted[sorted.length - 1], std };
}

async function setupCommittee(um, algorithm, size) {
    const members = [];
    for (let i = 0; i < size; i++) {
        const kp = await um.generateKeyPair(algorithm);
        members.push({
            address: kp.address, publicKey: kp.publicKey, privateKey: kp.privateKey
        });
    }
    return members;
}

async function runOne({ mesher, tms, um, court, committee, algorithm }) {
    const evidenceId = `BENCH-${algorithm}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

    // Upload (police side): encrypt + store on IPFS. New content per
    // iteration so IPFS never deduplicates an earlier upload.
    const fd = fs.openSync(evidenceFile, 'r+'); fs.writeSync(fd, crypto.randomBytes(32), 0, 32, 0); fs.closeSync(fd);
    const uploadStart = Date.now();
    const stored = await evidenceEncryption.storeEncryptedEvidence(ipfsClients, evidenceFile, {
        evidenceId, recipients: evidenceEncryption.loadRecipients(), workDir
    });
    const uploadMs = Date.now() - uploadStart;

    // Build metadata (cid = envelope CID of the encrypted evidence)
    const metadata = {
        evidenceId, cid: stored.envelopeCid,
        algorithm, timestamp: Date.now(), fileSize: stored.envelope.plaintextSize
    };
    const metadataHash = crypto.createHash('sha256').update(JSON.stringify(metadata)).digest('hex');

    // Setup, not timed: the evidence record exists on Fabric before a transfer
    if (fabricFixtures.isReal()) await fabricFixtures.submitEvidence(evidenceId, metadataHash);

    // Sign (per-call console logging suppressed in timed crypto sections,
    // as in benchmark-crypto-1000.js and measure-bundle-size.js)
    const log = console.log;
    console.log = () => {};
    const signStart = Date.now();
    const partials = [];
    for (let i = 0; i < T; i++) {
        const p = await tms.generatePartialSignature({
            privateKey: committee[i].privateKey,
            publicKey:  committee[i].publicKey,
            memberAddress: committee[i].address,
            evidenceHash: metadataHash,
            algorithm
        });
        partials.push(p);
    }
    const signMs = Date.now() - signStart;

    // Combine
    const combineStart = Date.now();
    const bundle = await tms.combinePartialSignatures(partials, T);
    const combineMs = Date.now() - combineStart;
    console.log = log;

    const bundleJsonBytes  = tms.serializeBundle(bundle).length / 2;  // legacy JSON size

    // 2PC transfer
    const transferResult = await mesher.transfer({
        evidenceId: metadata.evidenceId,
        metadataHash,
        multiSigBundle: bundle,
        algorithm,
        signerSet: committee.slice(0, T).map(m => m.address)
    });

    // Court-side verification (bundle against registered committee)
    const registered = committee.map(m => ({ address: m.address, publicKey: m.publicKey }));
    console.log = () => {};
    const verifyStart = Date.now();
    const vr = await tms.verifyMultiSignature(bundle, metadataHash, registered);
    const verifyMs = Date.now() - verifyStart;
    console.log = log;

    return {
        uploadMs, encryptMs: stored.timings.encryptMs,
        signMs, combineMs, verifyMs, bundleJsonBytes,
        bundleSizeBytes: transferResult.bundle?.size || 0,
        storeMs: transferResult.phaseTimings?.store || 0,
        prepareMs: transferResult.phaseTimings?.prepare || 0,
        finalizeMs: transferResult.phaseTimings?.finalize || 0,
        totalMs: transferResult.phaseTimings?.total || 0,
        outcome: transferResult.outcome,
        verifyOk: vr.isValid
    };
}

async function benchAlgo(algorithm) {
    console.log(`\n════════ ${algorithm} ════════`);

    const um     = new UserManager();
    const tms    = new ThresholdMultiSignature(um);
    const court  = new RealUnsigncryption();
    const mesher = new CompleteCrossChainMesher();

    const committee = await setupCommittee(um, algorithm, N);

    // Warmup: 2 iterations, not recorded
    for (let i = 0; i < 2; i++) {
        await runOne({ mesher, tms, um, court, committee, algorithm }).catch(() => {});
    }

    const runs = [];
    for (let i = 0; i < ITER; i++) {
        try {
            const r = await runOne({ mesher, tms, um, court, committee, algorithm });
            runs.push(r);
            if ((i + 1) % 5 === 0) console.log(`   progress: ${i + 1}/${ITER}`);
        } catch (e) {
            console.log(`   ⚠️  iteration ${i} failed: ${e.message}`);
        }
    }

    const kept = runs.filter(r => r.outcome === 'COMMITTED' && r.verifyOk);
    console.log(`   ${kept.length}/${runs.length} iterations COMMITTED and verified`);

    const aggregate = {
        algorithm,
        iterations: kept.length,
        upload:   stats(kept.map(r => r.uploadMs)),
        encrypt:  stats(kept.map(r => r.encryptMs)),
        sign:     stats(kept.map(r => r.signMs)),
        combine:  stats(kept.map(r => r.combineMs)),
        store:    stats(kept.map(r => r.storeMs)),
        prepare:  stats(kept.map(r => r.prepareMs)),
        finalize: stats(kept.map(r => r.finalizeMs)),
        verify:   stats(kept.map(r => r.verifyMs)),
        total:    stats(kept.map(r => r.totalMs)),
        bundleBytes: stats(kept.map(r => r.bundleSizeBytes)),
        bundleJsonBytes: stats(kept.map(r => r.bundleJsonBytes))
    };
    return aggregate;
}

function formatRow(agg) {
    const pad = (s, w) => String(s).padStart(w);
    return [
        agg.algorithm.padEnd(12),
        pad(agg.iterations, 4),
        pad(agg.upload.mean.toFixed(0), 6),
        pad(agg.sign.mean.toFixed(1), 7),
        pad(agg.combine.mean.toFixed(1), 7),
        pad(agg.store.mean.toFixed(0), 5),
        pad(agg.prepare.mean.toFixed(0), 7),
        pad(agg.finalize.mean.toFixed(0), 8),
        pad(agg.verify.mean.toFixed(1), 7),
        pad(agg.total.mean.toFixed(0), 7),
        pad(agg.total.p95.toFixed(0), 7),
        pad(agg.bundleBytes.mean.toFixed(0), 8)
    ].join(' │ ');
}

async function main() {
    console.log('╔══════════════════════════════════════════════════════════════════════════╗');
    console.log('║  FULL END-TO-END: MULTI-SIG + 2PC + LIVE BESU                            ║');
    console.log('╚══════════════════════════════════════════════════════════════════════════╝');
    console.log(`  Iterations per algorithm: ${ITER}`);
    console.log(`  Committee size:           ${T}/${N}`);
    console.log(`  Algorithms:               ${ALGOS.join(', ')}`);
    console.log(`  Fabric mode:              ${process.env.FABRIC_MODE}`);
    console.log(`  Evidence file:            ${FILE_MB} MB, encrypted, ${IPFS_URLS.length} IPFS replica(s)`);
    console.log('');
    console.log('  ⚠️  This benchmark drives the REAL 2PC coordinator against live Besu.');
    console.log('     Each iteration writes a transfer to Besu (cannot be undone).');

    const fdInit = fs.openSync(evidenceFile, 'w');
    for (let off = 0; off < FILE_MB * 1024 * 1024; off += 8 * 1024 * 1024) {
        fs.writeSync(fdInit, crypto.randomBytes(Math.min(8 * 1024 * 1024, FILE_MB * 1024 * 1024 - off)));
    }
    fs.closeSync(fdInit);

    const results = [];
    for (const algo of ALGOS) {
        try {
            results.push(await benchAlgo(algo));
        } catch (e) {
            console.error(`   ❌ ${algo} benchmark failed: ${e.message}`);
        }
    }

    console.log('\n╔══════════════════════════════════════════════════════════════════════════╗');
    console.log('║  RESULTS (mean latency per phase, ms)                                    ║');
    console.log('╚══════════════════════════════════════════════════════════════════════════╝');
    console.log('Algorithm    │ iter │ upload │ sign(t) │ combine │ store │ prepare │ finalize │ verify │  total │ p95    │ bundle(B)');
    console.log('─────────────┼──────┼────────┼─────────┼─────────┼───────┼─────────┼──────────┼────────┼────────┼────────┼──────────');
    for (const r of results) console.log(formatRow(r));
    console.log('');

    // Save JSON artifact for later analysis
    const outDir = path.resolve(__dirname, './test-scripts/test-results/revision');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    const outPath = path.join(outDir, `benchmark-multisig-2pc-${Date.now()}.json`);
    fs.writeFileSync(outPath, JSON.stringify({
        config: {
            iterations: ITER, t: T, n: N, algorithms: ALGOS, fabricMode: process.env.FABRIC_MODE,
            evidenceFileMB: FILE_MB, ipfsReplicas: IPFS_URLS.length,
            bundleMinReplicas: process.env.BUNDLE_MIN_REPLICAS ?? 'all',
            bundleIpfsUrls: process.env.BUNDLE_IPFS_URLS ?? 'http://127.0.0.1:5001 (default)'
        },
        results,
        timestamp: new Date().toISOString()
    }, null, 2));
    console.log(`📁 Detailed results saved to: ${outPath}`);

    // Honest note for the paper
    if (process.env.FABRIC_MODE !== 'real') {
        console.log('\n📋 NOTE: FABRIC_MODE is not "real"; prepare/finalize reflect Besu only.');
    }
    await fabricFixtures.close();
    fs.rmSync(workDir, { recursive: true, force: true });
    process.exit(0);
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
