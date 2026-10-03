// Simplified performance monitoring - Terminal output only
class CryptoPerformanceMonitor {
    constructor() {
        console.log('📊 Crypto Performance Monitor: Terminal Output Mode');
    }

    // Key Generation Performance
    recordKeyGeneration(algorithm, generationTimeMs, keySizes = {}) {
        console.log(`🔑 ${algorithm} Key Generation: ${generationTimeMs}ms`);
        if (keySizes.publicKeySize) {
            console.log(`   Public Key: ${keySizes.publicKeySize} bytes`);
        }
        if (keySizes.privateKeySize) {
            console.log(`   Private Key: ${keySizes.privateKeySize} bytes`);
        }
    }

    // Digital Signature Performance
    recordSignatureCreation(algorithm, creationTimeMs, signatureSize = null) {
        console.log(`🔐 ${algorithm} Signature Creation: ${creationTimeMs}ms`);
        if (signatureSize) {
            console.log(`   Signature Size: ${signatureSize} bytes`);
        }
    }

    recordSignatureVerification(algorithm, verificationTimeMs, isValid = true) {
        console.log(`🔍 ${algorithm} Signature Verification: ${verificationTimeMs}ms (${isValid ? 'VALID' : 'INVALID'})`);
        this.recordSignatureVerificationCount(isValid ? 'success' : 'error', algorithm);
    }

    // Operation Counters
    recordEvidenceUpload(status = 'success', algorithm = 'ECC') {
        console.log(`📁 Evidence Upload: ${status.toUpperCase()} (Algorithm: ${algorithm})`);
    }

    recordSignatureVerificationCount(status = 'success', algorithm = 'ECC') {
        console.log(`🔍 Signature Verification: ${status.toUpperCase()} (Algorithm: ${algorithm})`);
    }

    recordUserRegistration(status = 'success', algorithm = 'ECC') {
        console.log(`👤 User Registration: ${status.toUpperCase()} (Algorithm: ${algorithm})`);
    }

    recordOwnershipTransfer(status = 'success') {
        console.log(`🔄 Ownership Transfer: ${status.toUpperCase()}`);
    }

    recordBlockchainTransaction(type) {
        console.log(`⛓️ Blockchain Transaction: ${type.toUpperCase()}`);
    }

}

// Create singleton instance
const monitor = new CryptoPerformanceMonitor();

module.exports = {
    recordKeyGeneration: (algorithm, time, keySizes) => monitor.recordKeyGeneration(algorithm, time, keySizes),
    recordSignatureCreation: (algorithm, time, size) => monitor.recordSignatureCreation(algorithm, time, size),
    recordSignatureVerification: (algorithm, time, isValid) => monitor.recordSignatureVerification(algorithm, time, isValid),
    recordEvidenceUpload: (status, algorithm) => monitor.recordEvidenceUpload(status, algorithm),
    recordSignatureVerificationCount: (status, algorithm) => monitor.recordSignatureVerificationCount(status, algorithm),
    recordUserRegistration: (status, algorithm) => monitor.recordUserRegistration(status, algorithm),
    recordOwnershipTransfer: (status) => monitor.recordOwnershipTransfer(status),
    recordBlockchainTransaction: (type) => monitor.recordBlockchainTransaction(type),
    
    // For compatibility - empty functions
    metricsMiddleware: (req, res, next) => next(),
    promClient: null,
    cryptoMetrics: {}
};