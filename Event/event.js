const { profile } = require('./profile');
const { Wallets, Gateway } = require('fabric-network');
const path = require('path');
const fs = require('fs');

class EventListener {
    async blockEventListener(role, identityLabel, channelName) {
        const gateway = new Gateway();
        try {
            // Load profile configuration
            const userProfile = profile[role.toLowerCase()];
            const cpPath = path.resolve(userProfile["CP"]);
            const ccp = JSON.parse(fs.readFileSync(cpPath, 'utf8'));
            const wallet = await Wallets.newFileSystemWallet(userProfile["Wallet"]);

            // Connect to the Fabric network
            await gateway.connect(ccp, {
                wallet,
                identity: identityLabel,
                discovery: { enabled: true, asLocalhost: true }
            });

            const network = await gateway.getNetwork(channelName);

            console.log('🚀 Listening for new block events on channel:', channelName);

            // Register block listener
            await network.addBlockListener(async (event) => {
                console.log('\n🧱 ===============================');
                console.log(`🧩 New Block Detected: #${event.blockNumber.toString()}`);

                // Extract transactions from the block
                const blockData = event.blockData.data.data;
                for (const txEnvelope of blockData) {
                    const txPayload = txEnvelope.payload;
                    const header = txPayload.header;
                    const channelHeader = header.channel_header;
                    const signatureHeader = header.signature_header;

                    const txId = channelHeader.tx_id;
                    const timestamp = channelHeader.timestamp;
                    const mspId = signatureHeader.creator.Mspid;

                    console.log(`🔹 Transaction ID: ${txId}`);
                    console.log(`🕒 Timestamp: ${timestamp}`);
                    console.log(`🏛 MSP ID: ${mspId}`);

                    try {
                        const actions = txPayload.data.actions;
                        if (actions && actions.length > 0) {
                            for (const action of actions) {
                                const inputArgs = action.payload.chaincode_proposal_payload.input.chaincode_spec.input.args.map(
                                    arg => Buffer.from(arg).toString('utf8')
                                );
                                console.log(`⚙️ Chaincode Function: ${inputArgs[0]}`);
                                console.log(`📦 Arguments: ${inputArgs.slice(1).join(', ')}`);
                            }
                        }
                    } catch (err) {
                        console.log('⚠️ Could not extract chaincode function details (possibly config/system transaction).');
                    }
                }
                console.log('🧱 ===============================\n');
            });

        } catch (error) {
            console.error(`❌ Error in block event listener: ${error.message}`);
            console.error(error.stack);
        } finally {
            // Keep listener alive — do not disconnect immediately
        }
    }
}

module.exports = { EventListener };
