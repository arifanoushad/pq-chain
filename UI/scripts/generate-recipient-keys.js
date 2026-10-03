// UI/scripts/generate-recipient-keys.js
//
// WP3: generate the ML-KEM-768 key pairs of the evidence recipients
// (PoliceOrg, CourtOrg). Public keys → UI/config/evidence-recipients.json;
// each organisation's secret key → UI/data/keys/<Org>.kem.json (mode 0600).
// In a deployment each organisation generates and keeps its own secret key;
// both files are local and not committed.
//
// Run:  cd UI && node scripts/generate-recipient-keys.js [--force]

const fs   = require('fs');
const path = require('path');
const pqSeal = require('../utils/pqSeal');
const { RECIPIENTS_FILE, KEYS_DIR } = require('../utils/evidenceEncryption');

const ORGS = ['PoliceOrg', 'CourtOrg'];

(async () => {
    if (fs.existsSync(RECIPIENTS_FILE) && !process.argv.includes('--force')) {
        console.log(`${RECIPIENTS_FILE} exists; use --force to replace (existing evidence would become unreadable)`);
        return;
    }
    fs.mkdirSync(path.dirname(RECIPIENTS_FILE), { recursive: true });
    fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    const recipients = {};
    for (const org of ORGS) {
        const kp = await pqSeal.generateKeyPair();
        recipients[org] = { kemPublicKey: kp.publicKey, alg: 'ML-KEM-768' };
        fs.writeFileSync(path.join(KEYS_DIR, `${org}.kem.json`),
            JSON.stringify({ org, alg: 'ML-KEM-768', kemSecretKey: kp.secretKey }, null, 2), { mode: 0o600 });
    }
    fs.writeFileSync(RECIPIENTS_FILE, JSON.stringify(recipients, null, 2));
    console.log(`Public keys: ${RECIPIENTS_FILE}\nSecret keys: ${KEYS_DIR}/<Org>.kem.json`);
})().catch(e => { console.error(e); process.exit(1); });
