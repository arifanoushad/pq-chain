const UserManager = require('./utils/userManager');

async function benchmarkCrypto() {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║     BENCHMARK 1: CRYPTO OPERATIONS (1000 iterations)         ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const um = new UserManager();
    
    // Silence console logs for accurate timing
    const originalLog = console.log;
    console.log = () => {};
    
    const algorithms = ['ECC', 'DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5'];
    const ITERATIONS = 1000;
    const results = {};
    
    for (const algo of algorithms) {
        console.log(`\n📊 Testing ${algo} (${ITERATIONS} iterations)...`);
        
        const keyGenTimes = [];
        const signTimes = [];
        const verifyTimes = [];
        
        // Warm-up (2 iterations)
        for (let w = 0; w < 2; w++) {
            const warmKeys = await um.generateKeyPair(algo);
            const warmSig = await um.createSignature(warmKeys.privateKey, 'warmup', algo);
            await um.verifySignature(warmKeys.publicKey, 'warmup', warmSig.signature, algo);
        }
        
        for (let i = 0; i < ITERATIONS; i++) {
            // Key Generation
            const kgStart = Date.now();
            const keys = await um.generateKeyPair(algo);
            keyGenTimes.push(Date.now() - kgStart);
            
            // Signing
            const testData = `PQ-Chain benchmark iteration ${i} for ${algo}`;
            const signStart = Date.now();
            const signature = await um.createSignature(keys.privateKey, testData, algo);
            signTimes.push(Date.now() - signStart);
            
            // Verification
            const verifyStart = Date.now();
            await um.verifySignature(keys.publicKey, testData, signature.signature, algo);
            verifyTimes.push(Date.now() - verifyStart);
        }
        
        // Calculate statistics
        const avgKeyGen = keyGenTimes.reduce((a,b) => a+b, 0) / ITERATIONS;
        const avgSign = signTimes.reduce((a,b) => a+b, 0) / ITERATIONS;
        const avgVerify = verifyTimes.reduce((a,b) => a+b, 0) / ITERATIONS;
        
        signTimes.sort((a,b) => a-b);
        const p95Sign = signTimes[Math.floor(ITERATIONS * 0.95)];
        const minSign = signTimes[0];
        const maxSign = signTimes[ITERATIONS - 1];
        
        const stdDevSign = Math.sqrt(signTimes.map(x => Math.pow(x - avgSign, 2)).reduce((a,b) => a+b, 0) / ITERATIONS);
        
        results[algo] = {
            keyGen: avgKeyGen,
            sign: avgSign,
            verify: avgVerify,
            p95Sign: p95Sign,
            minSign: minSign,
            maxSign: maxSign,
            stdDevSign: stdDevSign,
            keySize: (await um.generateKeyPair(algo)).keySize.public,
            sigSize: SIGNATURE_SIZES[algo]
        };
    }
    
    // Restore console.log
    console.log = originalLog;
    
    // Results Table
    console.log('\n\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║     CRYPTO OPERATIONS RESULTS (1000 iterations)               ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log('Algorithm     │ KeyGen(ms) │ Sign(ms) │ Verify(ms) │ 95th% │ Min │ Max │ StdDev');
    console.log('──────────────┼────────────┼──────────┼────────────┼───────┼─────┼─────┼───────');
    
    for (const [algo, data] of Object.entries(results)) {
        console.log(`${algo.padEnd(12)} │ ${data.keyGen.toFixed(2).padStart(10)} │ ${data.sign.toFixed(2).padStart(8)} │ ${data.verify.toFixed(2).padStart(10)} │ ${data.p95Sign.toFixed(0).padStart(5)} │ ${data.minSign} │ ${data.maxSign} │ ${data.stdDevSign.toFixed(2)}`);
    }
    
    console.log('\n✅ Crypto Benchmark Complete!');
}

const SIGNATURE_SIZES = {
    'ECC': 72,
    'DILITHIUM2': 2420,
    'DILITHIUM3': 3309,
    'DILITHIUM5': 4627
};

benchmarkCrypto().catch(console.error);
