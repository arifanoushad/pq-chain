// UI/test-scripts/fabric-fixtures.js
//
// Setup helpers for tests and benchmarks against the live Fabric network
// (FABRIC_MODE=real). PrepareTransfer requires the evidence to exist on
// Fabric, as it does after the police upload flow; these helpers register an
// uploader once and submit an evidence record before a transfer. They are
// setup steps and are never inside a timed phase.

const crypto = require('crypto');
const FabricTransferClient = require('../utils/fabricTransferClient');

let fixture = null;

async function getFixture() {
    if (!fixture) {
        fixture = (async () => {
            const client = new FabricTransferClient({ mode: 'real' });
            const { contract } = await client._connect();
            const address = crypto.randomBytes(20).toString('hex');
            await contract.submitTransaction('RegisterUser', 'benchmark uploader', 'uploader@test',
                'pk-' + address, address, new Date().toISOString());
            return { client, contract, address };
        })();
    }
    return fixture;
}

/** Submit an evidence record whose signed-data hash is the metadata hash. */
async function submitEvidence(evidenceId, metadataHash) {
    const { contract, address } = await getFixture();
    await contract.submitTransaction('SubmitEvidence', evidenceId, 'benchmark evidence',
        'bafy-' + evidenceId, 'application/octet-stream', address, 'sig-' + evidenceId, metadataHash);
}

async function close() {
    if (fixture) {
        const { client } = await fixture;
        await client.close();
        fixture = null;
    }
}

module.exports = { isReal: () => (process.env.FABRIC_MODE || '').toLowerCase() === 'real', submitEvidence, close };
