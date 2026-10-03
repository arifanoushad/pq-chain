const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const fs = require('fs');
const path = require('path');

const { 
    recordKeyGeneration, 
    recordSignatureCreation, 
    recordSignatureVerification
} = require('./cryptoPerformanceMonitor');

// Will be initialized dynamically
let ml_dsa44, ml_dsa65, ml_dsa87;

// Function to load noble modules (called when needed)
async function loadNobleModules() {
    if (!ml_dsa44) {
        const noble = await import('@noble/post-quantum/ml-dsa.js');
        ml_dsa44 = noble.ml_dsa44;
        ml_dsa65 = noble.ml_dsa65;
        ml_dsa87 = noble.ml_dsa87;
        console.log('✅ Loaded real Dilithium from @noble/post-quantum');
    }
}

class UserManager {
    constructor() {
        this.usersFile = path.resolve(__dirname, '../data/users.json');
        this.initUsersFile();
        
        // Algorithm parameters.  Sizes are the standard values in bytes
        // (ML-DSA: FIPS 204; ECC: secp256k1 uncompressed SEC 1 public key,
        // maximum DER-encoded ECDSA signature).  Timings are measured by the
        // benchmark scripts, never stored here.
        this.supportedAlgorithms = {
            'ECC': {
                name: 'ECDSA-secp256k1',
                type: 'classical',
                security: 128,
                library: 'elliptic',
                available: true,
                sizes: { publicKey: 65, privateKey: 32, signatureMax: 72 }
            },
            'DILITHIUM2': {
                name: 'ML-DSA-44 (Dilithium2)',
                type: 'pqc',
                security: 128,
                library: '@noble/post-quantum',
                available: true,
                sizes: { publicKey: 1312, privateKey: 2560, signature: 2420 }
            },
            'DILITHIUM3': {
                name: 'ML-DSA-65 (Dilithium3)',
                type: 'pqc',
                security: 192,
                library: '@noble/post-quantum',
                recommended: true,
                available: true,
                sizes: { publicKey: 1952, privateKey: 4032, signature: 3309 }
            },
            'DILITHIUM5': {
                name: 'ML-DSA-87 (Dilithium5)',
                type: 'pqc',
                security: 256,
                library: '@noble/post-quantum',
                available: true,
                sizes: { publicKey: 2592, privateKey: 4896, signature: 4627 }
            }
        };

        console.log('🔧 PQC Research Framework: REAL ECC + REAL Dilithium (will load on demand)');
    }

    // ========== REAL KEY GENERATION ==========
    async generateKeyPair(algorithm = 'DILITHIUM3') {
        console.log(`🔑 Generating key pair with algorithm: ${algorithm}`);
        
        if (!this.supportedAlgorithms[algorithm]) {
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }

        const startTime = Date.now();
        
        // For ECC: REAL crypto
        if (algorithm === 'ECC') {
            const keyPair = this.generateRealECCKeyPair();
            const generationTime = Date.now() - startTime;
            
            recordKeyGeneration(algorithm, generationTime, {
                publicKeySize: keyPair.keySize.public,
                privateKeySize: keyPair.keySize.private
            });

            console.log(`✅ ${algorithm} key pair generated in ${generationTime}ms (REAL ECC)`);
            console.log(`   Public Key: ${keyPair.keySize.public} bytes, Private Key: ${keyPair.keySize.private} bytes`);
            
            return keyPair;
        }
        
        // Load noble modules if not already loaded
        await loadNobleModules();
        
        // For Dilithium: REAL crypto from noble
        let keys;
        switch(algorithm) {
            case 'DILITHIUM2':
                keys = ml_dsa44.keygen();
                break;
            case 'DILITHIUM3':
                keys = ml_dsa65.keygen();
                break;
            case 'DILITHIUM5':
                keys = ml_dsa87.keygen();
                break;
            default:
                throw new Error(`Unknown algorithm: ${algorithm}`);
        }
        
        const generationTime = Date.now() - startTime;
        
        // Convert Uint8Array to base64 for storage
        const privateKeyBase64 = Buffer.from(keys.secretKey).toString('base64');
        const publicKeyBase64 = Buffer.from(keys.publicKey).toString('base64');
        
        recordKeyGeneration(algorithm, generationTime, {
            publicKeySize: keys.publicKey.length,
            privateKeySize: keys.secretKey.length
        });

        console.log(`✅ ${algorithm} key pair generated in ${generationTime}ms (REAL Dilithium)`);
        console.log(`   Public Key: ${keys.publicKey.length} bytes, Private Key: ${keys.secretKey.length} bytes`);
        
        return {
            publicKey: publicKeyBase64,
            privateKey: privateKeyBase64,
            address: this.getAddressFromPublicKey(publicKeyBase64),
            algorithm: algorithm,
            keySize: {
                public: keys.publicKey.length,
                private: keys.secretKey.length
            },
            performance: {
                generationTime: generationTime
            },
            implementation: 'real'
        };
    }

    generateRealECCKeyPair() {
        const keyPair = ec.genKeyPair();
        const publicKey = keyPair.getPublic('hex');
        const privateKey = keyPair.getPrivate('hex');
        
        return {
            publicKey: publicKey,
            privateKey: privateKey,
            address: this.getAddressFromPublicKey(publicKey),
            algorithm: 'ECC',
            keySize: {
                public: publicKey.length / 2,
                private: privateKey.length / 2
            },
            performance: {
                generationTime: 0
            },
            implementation: 'real'
        };
    }

    // ========== REAL SIGNATURE CREATION ==========
    async createSignature(privateKey, data, algorithm = 'DILITHIUM3') {
        console.log(`🔐 Creating signature with algorithm: ${algorithm}`);
        
        const startTime = Date.now();
        
        // For ECC: REAL crypto
        if (algorithm === 'ECC') {
            const signatureResult = this.createRealECCSignature(privateKey, data);
            const creationTime = Date.now() - startTime;
            
            recordSignatureCreation(algorithm, creationTime, signatureResult.signatureSize);
            
            console.log(`✅ ${algorithm} signature created in ${creationTime}ms (REAL ECC)`);
            console.log(`   Signature size: ${signatureResult.signatureSize} bytes`);
            
            return signatureResult;
        }
        
        // Load noble modules if not already loaded
        await loadNobleModules();
        
        // For Dilithium: REAL crypto from noble
        let secretKey;
        let signFn;
        
        switch(algorithm) {
            case 'DILITHIUM2':
                secretKey = Buffer.from(privateKey, 'base64');
                signFn = ml_dsa44.sign;
                break;
            case 'DILITHIUM3':
                secretKey = Buffer.from(privateKey, 'base64');
                signFn = ml_dsa65.sign;
                break;
            case 'DILITHIUM5':
                secretKey = Buffer.from(privateKey, 'base64');
                signFn = ml_dsa87.sign;
                break;
            default:
                throw new Error(`Unknown algorithm: ${algorithm}`);
        }
        
        const message = Buffer.from(data);
        const signature = signFn(message, secretKey);
        const creationTime = Date.now() - startTime;
        
        // Convert signature to hex for storage
        const signatureHex = Buffer.from(signature).toString('hex');
        
        recordSignatureCreation(algorithm, creationTime, signature.length);
        
        console.log(`✅ ${algorithm} signature created in ${creationTime}ms (REAL Dilithium)`);
        console.log(`   Signature size: ${signature.length} bytes`);
        
        return {
            signature: signatureHex,
            algorithm: algorithm,
            dataHash: crypto.createHash('sha256').update(data).digest('hex'),
            timestamp: new Date().toISOString(),
            signatureSize: signature.length,
            performance: {
                creationTime: creationTime
            },
            implementation: 'real'
        };
    }

    createRealECCSignature(privateKey, data) {
        const keyPair = ec.keyFromPrivate(privateKey, 'hex');
        const dataHash = crypto.createHash('sha256').update(data).digest('hex');
        const signature = keyPair.sign(dataHash);
        const signatureDER = signature.toDER('hex');
        
        return {
            signature: signatureDER,
            publicKey: keyPair.getPublic('hex'),
            dataHash: dataHash,
            timestamp: new Date().toISOString(),
            algorithm: 'ECC',
            signatureSize: signatureDER.length / 2,
            performance: {
                creationTime: 0
            },
            implementation: 'real'
        };
    }

    // ========== REAL SIGNATURE VERIFICATION ==========
    async verifySignature(publicKey, data, signature, algorithm = 'DILITHIUM3') {
        // Start timer IMMEDIATELY - before any console.log
        const startTime = Date.now();
        
        // For ECC: REAL crypto
        if (algorithm === 'ECC') {
            const verificationResult = this.verifyRealECCSignature(publicKey, data, signature);
            const verificationTime = Date.now() - startTime;
            
            recordSignatureVerification(algorithm, verificationTime, verificationResult.isValid);
            
            // Console.log AFTER timing (optional, can be removed for benchmarks)
            // console.log(`✅ ${algorithm} signature verified in ${verificationTime}ms`);
            
            return {
                ...verificationResult,
                verificationTime: verificationTime  // ← Add actual time
            };
        }
        
        // For Dilithium
        await loadNobleModules();
        
        let pubKey, verifyFn, sigBuffer;
        switch(algorithm) {
            case 'DILITHIUM2':
                pubKey = Buffer.from(publicKey, 'base64');
                verifyFn = ml_dsa44.verify;
                break;
            case 'DILITHIUM3':
                pubKey = Buffer.from(publicKey, 'base64');
                verifyFn = ml_dsa65.verify;
                break;
            case 'DILITHIUM5':
                pubKey = Buffer.from(publicKey, 'base64');
                verifyFn = ml_dsa87.verify;
                break;
            default:
                throw new Error(`Unknown algorithm: ${algorithm}`);
        }
        
        sigBuffer = Buffer.from(signature, 'hex');
        const message = Buffer.from(data);
        const isValid = verifyFn(sigBuffer, message, pubKey);
        const verificationTime = Date.now() - startTime;
        
        recordSignatureVerification(algorithm, verificationTime, isValid);
        
        return {
            isValid: isValid,
            algorithm: algorithm,
            verificationTime: verificationTime,
            implementation: 'real'
        };
    }

    verifyRealECCSignature(publicKey, data, signature) {
        try {
            const keyPair = ec.keyFromPublic(publicKey, 'hex');
            const dataHash = crypto.createHash('sha256').update(data).digest('hex');
            const signatureBuffer = Buffer.from(signature, 'hex');
            const isValid = keyPair.verify(dataHash, signatureBuffer);
            
            return {
                isValid: isValid,
                algorithm: 'ECC',
                verificationTime: 0,
                implementation: 'real'
            };
        } catch (error) {
            console.error('❌ Error verifying ECC signature:', error);
            return {
                isValid: false,
                algorithm: 'ECC',
                error: error.message
            };
        }
    }

    // ========== UTILITY METHODS ==========
    
    getAddressFromPublicKey(publicKey) {
        try {
            const hash = crypto.createHash('sha256').update(publicKey).digest('hex');
            return hash.slice(0, 40);
        } catch (error) {
            console.error('❌ Error generating address:', error);
            throw error;
        }
    }

    getSupportedAlgorithms() {
        return this.supportedAlgorithms;
    }

    registerUser(name, email, publicKey, privateKey, address, algorithm = 'DILITHIUM3') {
        const users = this.getUsers();
        
        const newUser = {
            id: crypto.randomBytes(16).toString('hex'),
            name: name.trim(),
            email: email.trim(),
            publicKey: publicKey.trim(),
            privateKey: privateKey.trim(),
            address: address.trim(),
            algorithm: algorithm,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        this.saveUsers(users);
        
        return newUser;
    }

    loginUser(privateKey) {
        const users = this.getUsers();
        const trimmedPrivateKey = privateKey.trim();
        
        const foundUser = users.find(user => user.privateKey === trimmedPrivateKey);
        
        if (foundUser) {
            return foundUser;
        } else {
            throw new Error('Invalid private key');
        }
    }

    getUsers() {
        try {
            if (!fs.existsSync(this.usersFile)) {
                return [];
            }
            const data = fs.readFileSync(this.usersFile, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('❌ Error reading users file:', error);
            return [];
        }
    }

    saveUsers(users) {
        try {
            fs.writeFileSync(this.usersFile, JSON.stringify(users, null, 2));
        } catch (error) {
            console.error('❌ Error saving users:', error);
            throw error;
        }
    }

    initUsersFile() {
        if (!fs.existsSync(this.usersFile)) {
            const dir = path.dirname(this.usersFile);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.usersFile, JSON.stringify([]));
        }
    }

    async signEvidence(privateKey, evidenceData, algorithm = null) {
        const selectedAlgorithm = algorithm || evidenceData.algorithm || 'DILITHIUM3';
        console.log(`🔐 Signing evidence with algorithm: ${selectedAlgorithm}`);
        
        const evidenceString = JSON.stringify(evidenceData);
        const signatureResult = await this.createSignature(privateKey, evidenceString, selectedAlgorithm);
        
        console.log(`  - ${selectedAlgorithm} signature created successfully`);
        return signatureResult;
    }

    async verifyEvidenceSignature(publicKey, evidenceData, signature, algorithm = null) {
        const selectedAlgorithm = algorithm || evidenceData.algorithm || 'DILITHIUM3';
        console.log(`🔐 Verifying evidence signature with algorithm: ${selectedAlgorithm}`);
        
        const evidenceString = JSON.stringify(evidenceData);
        const verificationResult = await this.verifySignature(publicKey, evidenceString, signature, selectedAlgorithm);
        
        console.log(`  - ${selectedAlgorithm} signature valid:`, verificationResult.isValid);
        return verificationResult.isValid;
    }

    getAlgorithmDetails(algorithm) {
        return this.supportedAlgorithms[algorithm] || null;
    }

    getAllUsers() {
        return this.getUsers();
    }

    isValidPrivateKey(privateKey) {
        if (!privateKey || typeof privateKey !== 'string') {
            return false;
        }
        const cleanKey = privateKey.trim();
        if (cleanKey.length < 10) {
            return false;
        }
        return true;
    }

    detectAlgorithm(key) {
        if (typeof key === 'string') {
            if (key.length > 128 && /^[A-Za-z0-9+/=]+$/.test(key)) {
                return 'DILITHIUM3';
            } else if (/^[0-9a-fA-F]+$/.test(key)) {
                return 'ECC';
            }
        }
        return 'ECC';
    }
}


module.exports = UserManager;