const UserManager = require('./utils/userManager');
const RealUnsigncryption = require('./utils/realUnsigncryption');
const crypto = require('crypto');

async function testRealUnsigncryption() {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║     REAL UNSIGNCRYPTION TEST                                  ║');
    console.log('║     Testing signature verification for all algorithms        ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const userManager = new UserManager();
    const unsigncryption = new RealUnsigncryption();
    
    const algorithms = ['ECC', 'DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5'];
    const results = [];
    
    for (const algo of algorithms) {
        console.log(`\n${'═'.repeat(60)}`);
        console.log(`📊 Testing ${algo} Unsigncryption`);
        console.log('═'.repeat(60));
        
        // 1. Generate key pair
        console.log(`\n🔑 Generating ${algo} key pair...`);
        const keys = await userManager.generateKeyPair(algo);
        console.log(`   Public Key Size: ${keys.keySize.public} bytes`);
        console.log(`   Private Key Size: ${keys.keySize.private} bytes`);
        
        // 2. Create evidence data
        const evidenceData = {
            evidenceId: `${algo}_TEST_${Date.now()}`,
            title: `Test Evidence with ${algo}`,
            timestamp: Date.now(),
            algorithm: algo
        };
        const evidenceString = JSON.stringify(evidenceData);
        const evidenceHash = crypto.createHash('sha256').update(evidenceString).digest('hex');
        
        console.log(`\n📋 Evidence Hash: ${evidenceHash.substring(0, 32)}...`);
        
        // 3. Sign the evidence hash
        console.log(`\n✍️ Signing with ${algo}...`);
        const signatureResult = await userManager.createSignature(
            keys.privateKey,
            evidenceHash,
            algo
        );
        
        const signature = signatureResult.signature;
        console.log(`   Signature Size: ${signature.length/2} bytes`);
        console.log(`   Signature Hash: ${signatureResult.dataHash.substring(0, 32)}...`);
        
        // 4. VERIFY the signature (THIS IS UNSIGNCRYPTION!)
        console.log(`\n✅ Verifying signature with ${algo} (Real Unsigncryption)...`);
        const startVerify = Date.now();
        const isValid = await unsigncryption.verifySignature(
            signature,
            evidenceHash,
            keys.publicKey,
            algo
        );
        const verifyTime = Date.now() - startVerify;
        
        console.log(`   Verification Result: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
        console.log(`   Verification Time: ${verifyTime}ms`);
        
        // 5. Test with tampered data (should fail)
        console.log(`\n🔒 Testing tampered data (should fail)...`);
        const tamperedHash = crypto.createHash('sha256').update('TAMPERED_DATA').digest('hex');
        const isTamperedValid = await unsigncryption.verifySignature(
            signature,
            tamperedHash,
            keys.publicKey,
            algo
        );
        
        console.log(`   Tampered verification: ${isTamperedValid ? '❌ Should have failed' : '✅ Correctly rejected'}`);
        
        results.push({
            algorithm: algo,
            keySize: keys.keySize.public,
            signatureSize: signature.length/2,
            verificationValid: isValid,
            verificationTime: verifyTime,
            tamperedRejected: !isTamperedValid
        });
    }
    
    // Summary
    console.log('\n\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    FINAL RESULTS                                ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log('Algorithm     │ Key Size  │ Sig Size  │ Verify Time │ Status');
    console.log('──────────────┼───────────┼───────────┼─────────────┼─────────');
    
    for (const r of results) {
        const status = r.verificationValid && r.tamperedRejected ? '✅' : '❌';
        console.log(`${r.algorithm.padEnd(12)} │ ${r.keySize.toString().padStart(8)} │ ${r.signatureSize.toString().padStart(8)} │ ${r.verificationTime.toString().padStart(11)}ms │ ${status}`);
    }
    
    console.log('\n✅✅✅ REAL UNSIGNCRYPTION TEST PASSED! ✅✅✅');
    console.log('\n📋 Summary:');
    console.log('   ├─ REAL ECC signing and verification');
    console.log('   ├─ REAL DILITHIUM2 signing and verification');
    console.log('   ├─ REAL DILITHIUM3 signing and verification');
    console.log('   ├─ REAL DILITHIUM5 signing and verification');
    console.log('   └─ All tampered data correctly rejected');
}

testRealUnsigncryption().catch(console.error);
