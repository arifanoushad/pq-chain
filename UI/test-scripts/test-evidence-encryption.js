// UI/test-scripts/test-evidence-encryption.js
//
// WP3 (R1.3 / R2.W3): encrypt-before-IPFS. Offline checks with temporary
// ML-KEM-768 recipient keys, plus a live round trip through the IPFS nodes in
// BUNDLE_IPFS_URLS (default the local node) if they are reachable.
//
// Run:  cd UI && node test-scripts/test-evidence-encryption.js

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const pqSeal = require('../utils/pqSeal');
const enc    = require('../utils/evidenceEncryption');

let passed = 0, failed = 0;
function expect(cond, label, detail) {
    if (cond) { console.log('   ✅', label); passed++; }
    else      { console.log('   ❌', label); if (detail) console.log('      ', detail); failed++; }
}
async function rejects(fn, pattern) {
    try { await fn(); return { ok: false, msg: 'no error' }; }
    catch (e) { return { ok: pattern.test(e.message), msg: e.message }; }
}
const sha = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

async function main() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqchain-enc-'));
    const keys = {};
    for (const org of ['PoliceOrg', 'CourtOrg']) keys[org] = await pqSeal.generateKeyPair();
    const recipients = Object.fromEntries(Object.entries(keys).map(([o, k]) => [o, { kemPublicKey: k.publicKey }]));

    const plainPath = path.join(dir, 'evidence.bin');
    const marker = Buffer.from('PQ-CHAIN-PLAINTEXT-MARKER-'.repeat(4));
    fs.writeFileSync(plainPath, Buffer.concat([marker, crypto.randomBytes(3 * 1024 * 1024 + 17), marker]));
    const encPath = path.join(dir, 'evidence.enc');

    console.log('\n[1] Encrypt / decrypt');
    const env = await enc.encryptFile(plainPath, encPath, { evidenceId: 'CASE-ENC-1', recipients });
    const ct = fs.readFileSync(encPath);
    expect(ct.length === fs.statSync(plainPath).size && !ct.includes(marker), 'ciphertext has plaintext length and no plaintext marker');
    expect(env.wrappedKeys.length === 2 && env.plaintextSha256 === sha(plainPath) && !JSON.stringify(env).includes(marker.toString()),
        'envelope: 2 wrapped keys (PoliceOrg, CourtOrg) and plaintext SHA-256; no plaintext');
    for (const org of ['PoliceOrg', 'CourtOrg']) {
        const out = path.join(dir, `out-${org}.bin`);
        await enc.decryptFile(encPath, out, { ...env }, { recipient: org, kemSecretKey: keys[org].secretKey });
        expect(sha(out) === env.plaintextSha256, `${org} decrypts to the original file`);
    }

    console.log('\n[2] Rejections');
    const out = path.join(dir, 'out.bin');
    let r = await rejects(() => enc.decryptFile(encPath, out, env, { recipient: 'CourtOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /authentication failed/);
    expect(r.ok && !fs.existsSync(out), 'wrong secret key for the recipient → rejected, no output', r.msg);
    r = await rejects(() => enc.decryptFile(encPath, out, env, { recipient: 'DefenceOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /no wrapped key/);
    expect(r.ok, 'non-recipient → rejected', r.msg);
    const bad = Buffer.from(ct); bad[12345] ^= 1;
    const badPath = path.join(dir, 'bad.enc'); fs.writeFileSync(badPath, bad);
    r = await rejects(() => enc.decryptFile(badPath, out, env, { recipient: 'PoliceOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /authentication failed/);
    expect(r.ok && !fs.existsSync(out), 'one flipped ciphertext bit → rejected, no output', r.msg);
    r = await rejects(() => enc.decryptFile(encPath, out, { ...env, evidenceId: 'CASE-OTHER' }, { recipient: 'PoliceOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /authentication failed/);
    expect(r.ok, 'ciphertext presented under another evidence ID → rejected (AAD)', r.msg);
    const tag = Buffer.from(env.tag, 'base64'); tag[0] ^= 1;
    r = await rejects(() => enc.decryptFile(encPath, out, { ...env, tag: tag.toString('base64') }, { recipient: 'PoliceOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /authentication failed/);
    expect(r.ok, 'altered GCM tag → rejected', r.msg);
    r = await rejects(() => enc.decryptFile(encPath, out, { ...env, plaintextSha256: '00'.repeat(32) }, { recipient: 'PoliceOrg', kemSecretKey: keys.PoliceOrg.secretKey }), /hash does not match/);
    expect(r.ok && !fs.existsSync(out), 'envelope with a different plaintext hash → rejected', r.msg);
    const env2 = await enc.encryptFile(plainPath, path.join(dir, 'e2.enc'), { evidenceId: 'CASE-ENC-1', recipients });
    expect(env2.iv !== env.iv && sha(path.join(dir, 'e2.enc')) !== sha(encPath), 'fresh data key and IV per encryption');

    console.log('\n[3] Live IPFS round trip');
    const urls = (process.env.BUNDLE_IPFS_URLS ?? 'http://127.0.0.1:5001').split(',').map(s => s.trim()).filter(Boolean);
    const { create } = require('ipfs-http-client');
    const clients = urls.map(url => create({ url }));
    let live = true;
    try { await Promise.all(clients.map(c => c.version())); } catch (e) { live = false; console.log('   ⚠️  IPFS not reachable, skipped:', e.message); }
    if (live) {
        const stored = await enc.storeEncryptedEvidence(clients, plainPath, { evidenceId: 'CASE-ENC-LIVE', recipients, workDir: dir });
        const pinned = await Promise.all(clients.map(async c => {
            const pins = [];
            for await (const p of c.pin.ls({ paths: [stored.envelopeCid, stored.ciphertextCid] })) pins.push(p);
            return pins.length === 2;
        }));
        expect(pinned.every(Boolean), `envelope and ciphertext pinned on ${clients.length} IPFS node(s)`);
        const chunks = []; for await (const c of clients[0].cat(stored.ciphertextCid)) chunks.push(c);
        expect(!Buffer.concat(chunks).includes(marker), 'IPFS holds ciphertext only');
        for (let i = 0; i < clients.length; i++) {
            const o = path.join(dir, `live-${i}.bin`);
            await enc.retrieveDecryptedEvidence(clients[i], stored.envelopeCid, o,
                { recipient: 'CourtOrg', kemSecretKey: keys.CourtOrg.secretKey, evidenceId: 'CASE-ENC-LIVE' });
            expect(sha(o) === sha(plainPath), `CourtOrg retrieves and decrypts from node ${urls[i]}`);
        }
        r = await rejects(() => enc.retrieveDecryptedEvidence(clients[0], stored.envelopeCid, path.join(dir, 'x.bin'),
            { recipient: 'CourtOrg', kemSecretKey: keys.CourtOrg.secretKey, evidenceId: 'CASE-OTHER' }), /different evidence ID/);
        expect(r.ok, 'envelope requested for another evidence ID → rejected', r.msg);
    }

    fs.rmSync(dir, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
