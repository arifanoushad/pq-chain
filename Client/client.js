const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

class ClientApplication {
    constructor() {
        this.ccpPath = path.resolve(__dirname, '../Network/vars/profiles/evidencechannel_connection_for_nodesdk.json');
        this.walletPath = path.resolve(__dirname, '../Network/vars/profiles/vscode/wallets/PoliceOrg.evidence.com');
    }

    async generateAndSubmitTxn(org, user, channel, chaincode, fcn, ...args) {
        try {
            console.log(`Setting up connection for role: ${org}, identity: ${user}`);
            
            // Load connection profile
            const ccp = JSON.parse(fs.readFileSync(this.ccpPath, 'utf8'));
            console.log(`📄 Looking for connection profile at: ${this.ccpPath}`);
            console.log(`✅ Loaded connection profile for: ${ccp.client ? ccp.client.organization : 'Unknown organization'}`);

            // Create wallet
            const wallet = await Wallets.newFileSystemWallet(this.walletPath);
            console.log(`📁 Wallet path: ${this.walletPath}`);

            // Check if user exists in wallet
            const identity = await wallet.get(user);
            if (!identity) {
                throw new Error(`Identity '${user}' not found in wallet`);
            }
            console.log(`✅ Identity '${user}' found in wallet`);

            // Create gateway and connect
            const gateway = new Gateway();
            await gateway.connect(ccp, {
                wallet,
                identity: user,
                discovery: { enabled: true, asLocalhost: true }
            });
            console.log('✅ Gateway connected successfully');

            // Get network and contract
            const network = await gateway.getNetwork(channel);
            console.log(`✅ Connected to channel: ${channel}`);

            const contract = network.getContract(chaincode);
            console.log(`✅ Got contract from chaincode: ${chaincode}`);

            console.log(`🚀 Submitting transaction: ${fcn}`);
            console.log(`   Channel: ${channel}, Chaincode: ${chaincode}, Function: ${fcn}`);
            console.log(`   Args:`, JSON.stringify(args));

            const result = await contract.submitTransaction(fcn, ...args);
            console.log('✅ Transaction submitted successfully');

            await gateway.disconnect();
            console.log('Disconnected from gateway...');

            return result.toString();

        } catch (error) {
            console.error(`❌ Error in generateAndSubmitTxn: ${error}`);
            throw error;
        }
    }

    async submitEvidenceTxn(org, user, channel, chaincode, fcn, ...args) {
        return await this.generateAndSubmitTxn(org, user, channel, chaincode, fcn, ...args);
    }

    async evaluateTransaction(org, user, channel, chaincode, fcn, ...args) {
        try {
            console.log(`🔍 Evaluating transaction: ${fcn}`);
            
            const ccp = JSON.parse(fs.readFileSync(this.ccpPath, 'utf8'));
            const wallet = await Wallets.newFileSystemWallet(this.walletPath);

            const identity = await wallet.get(user);
            if (!identity) {
                throw new Error(`Identity '${user}' not found in wallet`);
            }

            const gateway = new Gateway();
            await gateway.connect(ccp, {
                wallet,
                identity: user,
                discovery: { enabled: true, asLocalhost: true }
            });

            const network = await gateway.getNetwork(channel);
            const contract = network.getContract(chaincode);

            console.log(`🔍 Evaluating: ${fcn} with args:`, JSON.stringify(args));
            
            const result = await contract.evaluateTransaction(fcn, ...args);

            await gateway.disconnect();
            return result.toString();

        } catch (error) {
            console.error(`❌ Error in evaluateTransaction: ${error}`);
            throw error;
        }
    }

    // ✅ NEW: Submit evidence with signature
    async submitEvidenceWithSignature(evidenceID, title, cid, mimeType, uploaderAddress, signature, signedDataHash) {
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'SubmitEvidence',
            evidenceID,
            title,
            cid,
            mimeType,
            uploaderAddress,
            signature,
            signedDataHash
        );
    }

    // Verify an evidence signature OFF-CHAIN: the chaincode only stores the
    // signature, signed-data hash and the uploader's registered public key.
    // Fetches the record and the registered key from Fabric, rebuilds the
    // signed data (same fields as routes/evidenceRoutes.js), checks it against
    // the stored hash, and runs real ML-DSA / ECC verification.
    async verifyEvidenceSignature(evidenceID) {
        const crypto = require('crypto');
        const UserManager = require('../UI/utils/userManager');

        const evidence = await this.readEvidence(evidenceID);
        const uploader = await this.getUser(evidence.uploaderAddress);
        const algorithm = evidence.signatureAlgorithm || 'ECC';

        if (!evidence.signature || !evidence.signedDataHash) {
            return { isValid: false, reason: 'no signature stored for this evidence' };
        }
        if (evidence.publicKey && evidence.publicKey !== uploader.publicKey) {
            return { isValid: false, reason: 'stored public key is not the uploader\'s registered key' };
        }

        const signedData = JSON.stringify({
            evidenceID: evidence.evidenceId,
            title: evidence.title,
            cid: evidence.cid,
            mimeType: evidence.mimeType,
            uploaderAddress: evidence.uploaderAddress,
            algorithm
        });
        const hashMatches = crypto.createHash('sha256').update(signedData).digest('hex') === evidence.signedDataHash;
        if (!hashMatches) {
            return { isValid: false, reason: 'signed data does not match the stored signedDataHash' };
        }

        const vr = await new UserManager().verifySignature(uploader.publicKey, signedData, evidence.signature, algorithm);
        return { isValid: !!vr.isValid, algorithm, reason: vr.isValid ? undefined : 'signature verification failed' };
    }

    // ✅ UPDATED: Transfer evidence ownership method
    async transferEvidenceOwnership(evidenceID, newOwner) {
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'TransferOwnership',
            evidenceID,
            newOwner
        );
    }

    // ✅ UPDATED: Get evidence by owner method
    async getEvidenceByOwner(ownerID) {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'GetAllEvidence'
        );
        const allEvidence = JSON.parse(result.toString());
        return allEvidence.filter(evidence => evidence.ownerId === ownerID);
    }

    // ✅ NEW: Register user on blockchain
    async registerUser(name, email, publicKey, address) {
        const createdAt = new Date().toISOString();
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'RegisterUser',
            name,
            email,
            publicKey,
            address,
            createdAt
        );
    }

    // ✅ NEW: Get user by address
    async getUser(userAddress) {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'GetUser',
            userAddress
        );
        return JSON.parse(result.toString());
    }

    // ✅ NEW: Get all registered users
    async getAllUsers() {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'GetAllUsers'
        );
        return JSON.parse(result.toString());
    }

    // ✅ NEW: Check if user exists
    async userExists(userAddress) {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'UserExists',
            userAddress
        );
        return JSON.parse(result.toString());
    }

    // ✅ UPDATED: Submit evidence with uploader address (legacy method - without signature)
    async submitEvidence(evidenceID, title, cid, mimeType, uploaderAddress) {
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'SubmitEvidence',
            evidenceID,
            title,
            cid,
            mimeType,
            uploaderAddress
        );
    }

    // ✅ UPDATED: Get all evidence (now includes uploaderAddress and signature fields)
    async getAllEvidence() {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'GetAllEvidence'
        );
        return JSON.parse(result.toString());
    }

    // ✅ UPDATED: Read specific evidence (now includes signature fields)
    async readEvidence(evidenceID) {
        const result = await this.evaluateTransaction(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'ReadEvidence',
            evidenceID
        );
        return JSON.parse(result.toString());
    }

    // ✅ UPDATED: Update evidence status
    async updateEvidence(evidenceID, newStatus, additionalInfo) {
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'UpdateEvidence',
            evidenceID,
            newStatus,
            additionalInfo
        );
    }

    // ✅ UPDATED: Delete evidence
    async deleteEvidence(evidenceID) {
        return await this.submitEvidenceTxn(
            'policeorg',
            'Admin',
            'evidencechannel',
            'evidence',
            'DeleteEvidence',
            evidenceID
        );
    }
        // 🔽 NEW: Enhanced evidence submission with algorithm support 🔽
    // 🔽 FIXED: Enhanced evidence submission with algorithm support 🔽
async submitEvidenceWithSignatureEnhanced(evidenceID, title, cid, mimeType, uploaderAddress, signature, signedDataHash, algorithm, publicKey) {
        console.log('🔍 DEBUG: Enhanced method called with params:');
    console.log('  - evidenceID:', evidenceID);
    console.log('  - algorithm:', algorithm);
    console.log('  - publicKey length:', publicKey ? publicKey.length : 'undefined');
    console.log('  - signature length:', signature ? signature.length : 'undefined');
    console.log('  - signedDataHash:', signedDataHash);
    let gateway;
    try {
        console.log(`🔐 Submitting evidence with enhanced method - Algorithm: ${algorithm}`);
        
        const ccp = JSON.parse(fs.readFileSync(this.ccpPath, 'utf8'));
        const wallet = await Wallets.newFileSystemWallet(this.walletPath);
        const identity = await wallet.get('Admin');
        
        if (!identity) {
            throw new Error('Admin identity not found in wallet');
        }

        gateway = new Gateway();
        await gateway.connect(ccp, {
            wallet,
            identity: 'Admin',
            discovery: { enabled: true, asLocalhost: true }
        });

        const network = await gateway.getNetwork('evidencechannel');
        const contract = network.getContract('evidence');
        
        const result = await contract.submitTransaction(
            'SubmitEvidenceEnhanced',
            evidenceID,
            title,
            cid,
            mimeType,
            uploaderAddress,
            signature,
            signedDataHash,
            algorithm,
            publicKey
        );
        
        await gateway.disconnect();
        return result.toString();
    } catch (error) {
        if (gateway) {
            await gateway.disconnect();
        }
        console.error(`❌ Error submitting evidence with enhanced method: ${error}`);
        throw error;
    }
}

    // 🔽 NEW: Query evidence by algorithm 🔽
    async queryEvidenceByAlgorithm(algorithm) {
        try {
            console.log(`🔍 Querying evidence by algorithm: ${algorithm}`);
            const contract = await this.getContract();
            const result = await contract.evaluateTransaction('QueryEvidenceByAlgorithm', algorithm);
            return JSON.parse(result.toString());
        } catch (error) {
            console.error(`❌ Error querying evidence by algorithm: ${error}`);
            // Fallback: get all evidence and filter client-side
            const allEvidence = await this.getAllEvidence();
            return allEvidence.filter(evidence => 
                (evidence.signatureAlgorithm || 'ECC') === algorithm
            );
        }
    }

    // 🔽 NEW: Get algorithm statistics 🔽
    async getAlgorithmStatistics() {
        try {
            console.log('📈 Getting algorithm statistics...');
            const contract = await this.getContract();
            const result = await contract.evaluateTransaction('GetAlgorithmStatistics');
            return JSON.parse(result.toString());
        } catch (error) {
            console.error(`❌ Error getting algorithm statistics: ${error}`);
            // Generate statistics from existing evidence
            const allEvidence = await this.getAllEvidence();
            const stats = { totalEvidence: allEvidence.length, timestamp: new Date().toISOString() };
            
            allEvidence.forEach(evidence => {
                const algo = evidence.signatureAlgorithm || 'ECC';
                if (!stats[algo]) {
                    stats[algo] = { count: 0, securityLevel: 128 };
                }
                stats[algo].count++;
            });
            
            return stats;
        }
    }

    // 🔽 NEW: Enhanced user registration with preferred algorithm 🔽
    async registerUserEnhanced(name, email, publicKey, address, createdAt, preferredAlgorithm) {
    try {
        console.log(`👤 Registering user with preferred algorithm: ${preferredAlgorithm}`);
        // Remove this line: const createdAt = new Date().toISOString(); // ← DELETE THIS
        const contract = await this.getContract();
        const result = await contract.submitTransaction(
            'RegisterUserEnhanced',
            name,
            email,
            publicKey,
            address,
            createdAt,          // Use the parameter passed from authRoutes.js
            preferredAlgorithm
        );
        return result.toString();
    } catch (error) {
        console.error(`❌ Error with enhanced user registration: ${error}`);
        // Fallback to original registration
        return await this.registerUser(name, email, publicKey, address);
    }
}

    // 🔽 UTILITY: Get contract instance 🔽
    async getContract() {
        const ccp = JSON.parse(fs.readFileSync(this.ccpPath, 'utf8'));
        const wallet = await Wallets.newFileSystemWallet(this.walletPath);
        const identity = await wallet.get('Admin');
        
        if (!identity) {
            throw new Error('Admin identity not found in wallet');
        }

        const gateway = new Gateway();
        await gateway.connect(ccp, {
            wallet,
            identity: 'Admin',
            discovery: { enabled: true, asLocalhost: true }
        });

        const network = await gateway.getNetwork('evidencechannel');
        const contract = network.getContract('evidence');
        
        // Store gateway for cleanup
        this.gateway = gateway;
        return contract;
    }

    // 🔽 UTILITY: Cleanup gateway connection 🔽
    async disconnect() {
        if (this.gateway) {
            await this.gateway.disconnect();
            this.gateway = null;
        }
    }
}

module.exports = { ClientApplication };