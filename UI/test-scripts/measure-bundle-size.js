// UI/test-scripts/measure-bundle-size.js
//
// R1.4: multi-signature bundle size and sign / verify time as a function of
// the threshold t.  Uses the real key generation, signing, bundling and
// verification code (UserManager + ThresholdMultiSignature); nothing is
// estimated.
//
// Method (same as the paper's multi-signature table, Table 10): for each
// (algorithm, t) a committee of n = t + 2 members is generated once; then
// 2 warm-up iterations (discarded) and ITER measured iterations, each on a
// fresh random 32-byte metadata hash:
//   sign    - t partial signatures, sequential (total and per signer)
//   combine - combinePartialSignatures
//   encode  - canonical binary encoding (encodeBundle)
//   verify  - verifyMultiSignature against the n-member registry
// Timer: performance.now(); UserManager's per-call console logging is
// suppressed during measurement.
//
// Sizes per iteration:
//   canonicalBytes - encodeBundle() length: the stored bundle, whose SHA-256
//                    is anchored on-chain (reported size from the revision on)
//   noPkBytes      - canonicalBytes minus the embedded public keys (optional
//                    optimisation: keys referenced from the committee registry)
//   jsonBytes      - UTF-8 length of JSON.stringify(bundle): the value reported
//                    in the original paper (serializeBundle().length / 2)
//   hexChars       - length of serializeBundle() (hex of the JSON)
//
// Run:  cd UI && node test-scripts/measure-bundle-size.js
// Env:  BUNDLE_T (default 1,3,5,7,9,11,15,21), BUNDLE_ALGOS (default all four),
//       BUNDLE_ITER (default 20), BUNDLE_WARMUP (default 2)

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

const UserManager             = require('../utils/userManager');
const ThresholdMultiSignature = require('../utils/thresholdMultiSignature');

const T_VALUES = (process.env.BUNDLE_T || '1,3,5,7,9,11,15,21').split(',').map(Number);
const ALGOS    = (process.env.BUNDLE_ALGOS || 'ECC,DILITHIUM2,DILITHIUM3,DILITHIUM5').split(',');
const ITER     = Number(process.env.BUNDLE_ITER)   || 20;
const WARMUP   = Number(process.env.BUNDLE_WARMUP ?? 2);

function stats(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const p95  = sorted[Math.floor(arr.length * 0.95)] ?? sorted[sorted.length - 1];
    const std  = Math.sqrt(arr.map(x => (x - mean) ** 2).reduce((a, b) => a + b, 0) / arr.length);
    return { mean, p95, std, min: sorted[0], max: sorted[sorted.length - 1] };
}

async function timed(fn) {
    const t0 = performance.now();
    const value = await fn();
    return { value, ms: performance.now() - t0 };
}

async function runOne(tms, committee, algorithm, t) {
    const evidenceHash = crypto.randomBytes(32).toString('hex');
    const registry = committee.map(m => ({ address: m.address, publicKey: m.publicKey }));

    const sign = await timed(async () => {
        const partials = [];
        for (let i = 0; i < t; i++) {
            partials.push(await tms.generatePartialSignature({
                privateKey: committee[i].privateKey, publicKey: committee[i].publicKey,
                memberAddress: committee[i].address, evidenceHash, algorithm
            }));
        }
        return partials;
    });
    const combine = await timed(() => tms.combinePartialSignatures(sign.value, t));
    const encode  = await timed(() => ThresholdMultiSignature.encodeBundle(combine.value));
    const verify  = await timed(() => tms.verifyMultiSignature(combine.value, evidenceHash, registry));
    if (!verify.value.isValid) throw new Error(`bundle failed verification: ${algorithm} t=${t}: ${verify.value.reason}`);

    const pkBytes = ThresholdMultiSignature.BUNDLE_ALGORITHMS.find(a => a.name === algorithm).publicKeyBytes;
    return {
        signMs: sign.ms, combineMs: combine.ms, encodeMs: encode.ms, verifyMs: verify.ms,
        canonicalBytes: encode.value.length,
        noPkBytes:      encode.value.length - t * pkBytes,
        jsonBytes:      Buffer.byteLength(JSON.stringify(combine.value), 'utf8'),
        hexChars:       tms.serializeBundle(combine.value).length
    };
}

(async () => {
    const log = console.log;
    const quiet = async fn => { console.log = () => {}; try { return await fn(); } finally { console.log = log; } };

    const um  = await quiet(() => new UserManager());
    const tms = new ThresholdMultiSignature(um);
    const rows = [];

    log(`n = t + 2, ${WARMUP} warm-up + ${ITER} measured iterations per (algorithm, t)\n`);
    log('algorithm    t   n │ sign(ms) per-signer verify(ms) │ canonical(B) noPk(B)  json(B)');
    for (const algorithm of ALGOS) {
        for (const t of T_VALUES) {
            const n = t + 2;
            const committee = [];
            for (let i = 0; i < n; i++) committee.push(await quiet(() => um.generateKeyPair(algorithm)));

            for (let i = 0; i < WARMUP; i++) await quiet(() => runOne(tms, committee, algorithm, t));
            const runs = [];
            for (let i = 0; i < ITER; i++) runs.push(await quiet(() => runOne(tms, committee, algorithm, t)));

            const s = k => stats(runs.map(r => r[k]));
            const row = {
                algorithm, t, n, iterations: ITER,
                sign: s('signMs'), signPerSigner: stats(runs.map(r => r.signMs / t)),
                combine: s('combineMs'), encode: s('encodeMs'), verify: s('verifyMs'),
                canonicalBytes: s('canonicalBytes'), noPkBytes: s('noPkBytes'),
                jsonBytes: s('jsonBytes'), hexChars: s('hexChars')
            };
            rows.push(row);

            log(`${algorithm.padEnd(11)} ${String(t).padStart(2)} ${String(n).padStart(3)} │ ` +
                `${row.sign.mean.toFixed(1).padStart(8)} ${row.signPerSigner.mean.toFixed(2).padStart(10)} ${row.verify.mean.toFixed(1).padStart(10)} │ ` +
                `${row.canonicalBytes.mean.toFixed(0).padStart(12)} ${row.noPkBytes.mean.toFixed(0).padStart(7)} ${row.jsonBytes.mean.toFixed(0).padStart(8)}`);
        }
    }

    const outDir = path.resolve(__dirname, 'test-results/revision');
    fs.mkdirSync(outDir, { recursive: true });
    const outPath = path.join(outDir, `bundle-scaling-${Date.now()}.json`);
    fs.writeFileSync(outPath, JSON.stringify({
        generatedAt: new Date().toISOString(),
        node: process.version,
        platform: `${process.platform} ${process.arch}`,
        method: {
            committee: 'n = t + 2, generated once per (algorithm, t)',
            iterations: ITER, warmup: WARMUP,
            timer: 'performance.now(); UserManager console logging suppressed',
            sign: 't partial signatures, sequential (total); signPerSigner = sign / t',
            verify: 'verifyMultiSignature against the n-member registry'
        },
        definitions: {
            canonicalBytes: 'encodeBundle() length (stored bundle; SHA-256 anchored on-chain)',
            noPkBytes: 'canonicalBytes minus t embedded public keys (optional optimisation)',
            jsonBytes: 'UTF-8 length of JSON.stringify(bundle) (value in the original paper)',
            hexChars: 'serializeBundle() length (hex of the JSON)'
        },
        rows
    }, null, 2));
    log(`\nSaved ${outPath}`);
})().catch(e => { console.error(e); process.exit(1); });
