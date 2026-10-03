// UI/test-scripts/audit-bundle.js
//
// JISA R1.4: audit one committed transfer.  Reads the Besu and Fabric
// records, fetches the bundle by its on-chain bundleHash (IPFS, then the
// local archive), and verifies it (see utils/bundleAuditor.js).
//
// Run:
//   cd UI
//   node test-scripts/audit-bundle.js <txId> <registry.json>
// registry.json: JSON array of registered members, [{ "address": ..., "publicKey": ... }].
// Uses the same environment as the coordinator (V2_CONTRACT_ADDRESS,
// FABRIC_MODE, BUNDLE_IPFS_URLS, BUNDLE_ARCHIVE_DIR).

const fs = require('fs');

const BesuTransferClient      = require('../utils/besuTransferClient');
const FabricTransferClient    = require('../utils/fabricTransferClient');
const BundleStore             = require('../utils/bundleStore');
const ThresholdMultiSignature = require('../utils/thresholdMultiSignature');
const { auditTransfer }       = require('../utils/bundleAuditor');

(async () => {
    const [txId, registryPath] = process.argv.slice(2);
    if (!txId || !registryPath) {
        console.error('usage: node test-scripts/audit-bundle.js <txId> <registry.json>');
        process.exit(2);
    }
    const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));

    const res = await auditTransfer({
        txId,
        besu:   new BesuTransferClient(),
        fabric: new FabricTransferClient(),
        store:  new BundleStore(),
        tms:    new ThresholdMultiSignature(),
        registry
    });

    for (const c of res.checks) console.log(`${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
    console.log(res.ok ? `\nAUDIT PASSED (signers: ${res.signers.join(', ')})` : '\nAUDIT FAILED');
    process.exit(res.ok ? 0 : 1);
})().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
