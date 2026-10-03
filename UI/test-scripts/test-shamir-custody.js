// UI/test-scripts/test-shamir-custody.js
//
// (t,n) Shamir share custody for committee administration (paper Alg. 3,
// Theorem "(t,n) Secrecy for Committee Admin"):
//   - each member's share is sealed to that member's ML-KEM-768 key and stored
//     in its own file; the server holds no plaintext share and no member key;
//   - the secret is reconstructed only from shares submitted by >= t distinct
//     members and checked against a SHA-256 commitment;
//   - t-1 shares, duplicates, outsiders and wrong shares are rejected.
// Offline; uses a temporary data directory.
//
// Run:  cd UI && node test-scripts/test-shamir-custody.js

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const CommitteeManager = require('../utils/committeeManager');
const pqSeal           = require('../utils/pqSeal');

let passed = 0, failed = 0;
function expect(cond, label, detail) {
    if (cond) { console.log('   ✅', label); passed++; }
    else      { console.log('   ❌', label); if (detail) console.log('      ', detail); failed++; }
}
async function rejects(fn, pattern) {
    try { await fn(); return { ok: false, msg: 'no error' }; }
    catch (e) { return { ok: pattern.test(e.message), msg: e.message }; }
}

async function main() {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqchain-shamir-'));
    const cm = new CommitteeManager({ dataDir });
    const N = 5, T = 3;

    // Members: address + ML-KEM-768 key pair (the secret key stays with the member)
    const members = [];
    for (let i = 0; i < N; i++) {
        const kp = await pqSeal.generateKeyPair();
        members.push({ address: crypto.randomBytes(20).toString('hex'), name: `Officer ${i + 1}`, role: 'member',
                       kemPublicKey: kp.publicKey, kemSecretKey: kp.secretKey });
    }
    const committee = await cm.createCommittee({
        name: 'Police committee', type: 'police', threshold: T,
        members: members.map(({ kemSecretKey, ...pub }) => pub)
    }, { address: members[0].address });
    const secret = crypto.randomBytes(32).toString('hex');

    console.log('\n[1] Issue shares');
    const issued = await cm.generateCommitteeShares(committee.id, secret);
    expect(issued.sharesIssued === N && !JSON.stringify(issued).includes(secret), `${N} shares issued; secret not returned`);
    const files = fs.readdirSync(path.join(dataDir, 'shares', committee.id));
    expect(files.length === N && members.every(m => files.includes(`${m.address}.json`)), 'one share file per member');
    const stored = cm.getCommittee(committee.id);
    expect(stored.secretCommitment === crypto.createHash('sha256').update(secret).digest('hex') &&
           stored.members.every(m => m.hasShare), 'commitment stored and hasShare persisted for every member');
    expect(!fs.readdirSync(dataDir).includes('shares.json'), 'no single all-shares file');

    console.log('\n[2] Custody: only the member can open their share');
    const shares = [];
    for (const m of members) {
        shares.push(await CommitteeManager.openMemberShare(cm.getMemberShareRecord(committee.id, m.address), m.kemSecretKey));
    }
    const allFiles = files.map(f => fs.readFileSync(path.join(dataDir, 'shares', committee.id, f), 'utf8')).join('');
    expect(shares.every(s => /^[0-9a-f]+$/.test(s) && !allFiles.includes(s)), 'shares open with the owner key; no plaintext share on disk');
    const recA = cm.getMemberShareRecord(committee.id, members[0].address);
    let r = await rejects(() => CommitteeManager.openMemberShare(recA, members[1].kemSecretKey), /authentication failed/);
    expect(r.ok, "another member's key cannot open the share", r.msg);
    r = await rejects(() => CommitteeManager.openMemberShare({ ...recA, memberAddress: members[1].address }, members[0].kemSecretKey), /authentication failed/);
    expect(r.ok, 'share record re-labelled to another member is rejected (AAD)', r.msg);
    const tampered = JSON.parse(JSON.stringify(recA));
    const ct = Buffer.from(tampered.sealed.ciphertext, 'base64'); ct[0] ^= 1;
    tampered.sealed.ciphertext = ct.toString('base64');
    r = await rejects(() => CommitteeManager.openMemberShare(tampered, members[0].kemSecretKey), /authentication failed/);
    expect(r.ok, 'tampered sealed share is rejected', r.msg);

    const submit = idx => idx.map(i => ({ memberAddress: members[i].address, share: shares[i] }));

    console.log('\n[3] Reconstruction from t member-supplied shares');
    expect(await cm.getCommitteeSecret(committee.id, submit([0, 1, 2])) === secret, 't = 3 shares (members 1,2,3) reconstruct the secret');
    expect(await cm.getCommitteeSecret(committee.id, submit([1, 3, 4])) === secret, 'any t-subset works (members 2,4,5)');
    expect(await cm.getCommitteeSecret(committee.id, submit([0, 1, 2, 3, 4])) === secret, 'all n shares also work');

    console.log('\n[4] Rejections');
    r = await rejects(() => cm.getCommitteeSecret(committee.id, submit([0, 1])), /at least 3 distinct members/);
    expect(r.ok, 't-1 = 2 shares rejected', r.msg);
    r = await rejects(() => cm.getCommitteeSecret(committee.id, submit([0, 0, 1])), /at least 3 distinct members/);
    expect(r.ok, 'duplicate member counted once (2 distinct) → rejected', r.msg);
    r = await rejects(() => cm.getCommitteeSecret(committee.id,
        [...submit([0, 1]), { memberAddress: crypto.randomBytes(20).toString('hex'), share: shares[2] }]), /not a member/);
    expect(r.ok, 'share submitted by a non-member rejected', r.msg);
    const foreign = require('secrets.js-grempe').share(crypto.randomBytes(32).toString('hex'), N, T)[2];
    r = await rejects(() => cm.getCommitteeSecret(committee.id,
        [...submit([0, 1]), { memberAddress: members[2].address, share: foreign }]), /does not match the committee commitment/);
    expect(r.ok, 'wrong share among t shares rejected by the commitment check', r.msg);
    expect(['getCommitteeShares', 'getSharesForMember', 'saveShares', 'reconstructSecret'].every(f => typeof cm[f] === 'undefined'),
        'old single-file share API removed (nothing reads all n shares)');

    console.log('\n[5] Issuing requires member KEM keys');
    const noKeys = await cm.createCommittee({ name: 'No keys', type: 'police', threshold: 2,
        members: members.slice(0, 3).map(m => ({ address: m.address, name: m.name, role: m.role })) }, { address: members[0].address });
    r = await rejects(() => cm.generateCommitteeShares(noKeys.id, secret), /without an ML-KEM public key/);
    expect(r.ok, 'members without an ML-KEM public key → shares not issued', r.msg);

    fs.rmSync(dataDir, { recursive: true, force: true });
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
