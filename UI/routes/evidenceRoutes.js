const express = require('express');
const multer = require('multer');
const { create } = require('ipfs-http-client');
const { ClientApplication } = require('../../Client/client');
const UserManager = require('../utils/userManager');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// 🔽 ADDED: Performance Monitoring Imports 🔽
// 🔽 UPDATED: Import only what we need
const { 
    recordKeyGeneration, 
    recordSignatureCreation, 
    recordSignatureVerification, 
    recordEvidenceUpload,
    recordSignatureVerificationCount,
    recordOwnershipTransfer,
    recordBlockchainTransaction,
    recordUserRegistration
} = require('../utils/cryptoPerformanceMonitor');
// 🔼 END OF ADDITION 🔼

const router = express.Router();
const upload = multer({ dest: 'uploads/' });
const ipfs = create({ url: 'http://127.0.0.1:5001' });
const evidenceEncryption = require('../utils/evidenceEncryption');
// Organisation whose ML-KEM key this server instance holds for decryption
const EVIDENCE_ORG = process.env.EVIDENCE_ORG || 'PoliceOrg';
const clientApp = new ClientApplication();

// Initialize UserManager for PQC operations
const userManager = new UserManager();

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

// 🔽 NEW: PQC Algorithm Selection Middleware 🔽
const getAlgorithmPreference = (req) => {
    return req.session.user?.preferredAlgorithm || req.body?.algorithm || 'DILITHIUM3';
};

// Dashboard - Enhanced with PQC info
router.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const result = await clientApp.getAllEvidence();
        
        const evidenceList = result;
        const userEvidence = evidenceList.filter(evidence => 
            evidence.uploaderAddress === req.session.user.address
        );

        res.render('dashboard', {
            title: 'Dashboard - Evidence Management System',
            user: req.session.user,
            totalEvidence: evidenceList.length,
            userEvidence: userEvidence.length,
            recentEvidence: userEvidence.slice(0, 5),
            supportedAlgorithms: userManager.getSupportedAlgorithms()
        });
    } catch (error) {
        res.render('dashboard', {
            title: 'Dashboard - Evidence Management System',
            user: req.session.user,
            totalEvidence: 0,
            userEvidence: 0,
            recentEvidence: [],
            supportedAlgorithms: userManager.getSupportedAlgorithms()
        });
    }
});

// Home page redirects to dashboard if logged in, else to login
router.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// 🔽 ENHANCED: Upload evidence page with algorithm selection 🔽
router.get('/upload', requireAuth, (req, res) => {
    const supportedAlgorithms = userManager.getSupportedAlgorithms();
    
    res.render('uploadEvidence', {
        title: 'Upload Evidence - Evidence Management System',
        user: req.session.user,
        message: null,
        supportedAlgorithms: supportedAlgorithms,
        defaultAlgorithm: getAlgorithmPreference(req)
    });
});

// 🔽 ENHANCED: Handle file upload with PQC algorithm selection 🔽
router.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
    const uploadStartTime = Date.now();
    let signatureStartTime;

    try {
        const { evidenceID, title, algorithm } = req.body;
        const selectedAlgorithm = algorithm || getAlgorithmPreference(req);
        const filePath = req.file.path;
        const fileMimeType = req.file.mimetype;
        const originalFileName = req.file.originalname;

        console.log(`\n📁 ========== EVIDENCE UPLOAD DEBUG ==========`);
        console.log(`📁 Processing file: ${originalFileName} (${fileMimeType})`);
        console.log(`📁 Evidence ID: ${evidenceID}, Title: ${title}`);
        console.log(`🔐 Selected Algorithm: ${selectedAlgorithm}`);

        // Encrypt (AES-256-GCM, data key wrapped with ML-KEM-768 for PoliceOrg
        // and CourtOrg) and store ciphertext + envelope on IPFS. The signed
        // `cid` is the envelope CID (see utils/evidenceEncryption.js).
        const stored = await evidenceEncryption.storeEncryptedEvidence(ipfs, filePath, {
            evidenceId: evidenceID,
            recipients: evidenceEncryption.loadRecipients(),
            workDir: path.dirname(filePath)
        });
        const cid = stored.envelopeCid;
        console.log(`✅ Encrypted evidence stored: envelope ${cid}, ciphertext ${stored.ciphertextCid} (${stored.timings.totalMs} ms)`);

        // Create digital signature with selected algorithm
        const evidenceData = {
            evidenceID: evidenceID,
            title: title,
            cid: cid,
            mimeType: fileMimeType,
            uploaderAddress: req.session.user.address,
            algorithm: selectedAlgorithm
        };

        console.log('🔐 Creating digital signature for data:');
        console.log('Data to be signed:', JSON.stringify(evidenceData, null, 2));
        console.log('Using algorithm:', selectedAlgorithm);
        
        console.log('👤 User details:');
        console.log('  - Address:', req.session.user.address);
        console.log('  - Private Key (first 16 chars):', req.session.user.privateKey.substring(0, 16) + '...');

        signatureStartTime = Date.now();

        // 🔽 FIXED: Properly extract signature and public key for both ECC and PQC 🔽
        let signature;
        let publicKey;
        let dataHash;

        // In evidenceRoutes.js - fix the ECC signature extraction
if (selectedAlgorithm === 'ECC') {
    const signatureResult = await userManager.signEvidence(req.session.user.privateKey, evidenceData);
    
    console.log('🔍 ECC Signature result structure:', signatureResult);
    
    // Extract signature from the result object
    if (signatureResult && typeof signatureResult === 'object') {
        signature = signatureResult.signature; // Extract the signature string
        publicKey = signatureResult.publicKey || req.session.user.publicKey;
        dataHash = signatureResult.dataHash;
        
        // If signature is still an object, try to get the actual signature
        if (signature && typeof signature === 'object') {
            signature = signature.signature || signature.toString();
        }
    } else {
        // Fallback: use result as signature string
        signature = signatureResult;
        publicKey = req.session.user.publicKey;
        const evidenceString = JSON.stringify(evidenceData);
        dataHash = crypto.createHash('sha256').update(evidenceString).digest('hex');
    }
    
    console.log('🔍 ECC Signature extracted:', {
        signatureType: typeof signature,
        signatureLength: signature ? signature.length : 'undefined',
        signatureValue: signature ? signature.substring(0, 32) + '...' : 'undefined'
    });
} else {
    // PQC algorithms (existing code)
    const signatureResult = await userManager.signEvidence(req.session.user.privateKey, evidenceData, selectedAlgorithm);
    signature = signatureResult.signature;
    publicKey = signatureResult.publicKey || req.session.user.publicKey;
    dataHash = signatureResult.dataHash;
}

        const signatureCreationTime = Date.now() - signatureStartTime;
        recordSignatureCreation(selectedAlgorithm, signatureCreationTime, signature.length);
        console.log(`⏱️ ${selectedAlgorithm} signature creation time: ${signatureCreationTime}ms`);

        console.log('✅ Digital signature created:');
        console.log('  - Algorithm:', selectedAlgorithm);
        console.log('  - Signature:', signature.substring(0, 64) + '...');
        console.log('  - Signature length:', signature.length);
        console.log('  - Data Hash:', dataHash);
        console.log('  - Public Key (first 32 chars):', publicKey.substring(0, 32) + '...');

        // Test verification immediately to catch issues early
        console.log('🔍 Testing signature verification immediately...');
        let testVerification;
        if (selectedAlgorithm === 'ECC') {
            testVerification = userManager.verifyEvidenceSignature(
                publicKey,
                evidenceData,
                signature
            );
        } else {
            testVerification = await userManager.verifyEvidenceSignature(
                publicKey,
                evidenceData,
                signature,
                selectedAlgorithm
            );
        }
        console.log('  - Immediate test verification:', testVerification ? '✅ PASSED' : '❌ FAILED');

        // Submit to blockchain with signature
        console.log('🚀 Submitting to blockchain...');
        let result;
        
        // 🔽 FIXED: Pass all required parameters 🔽
        try {
            result = await clientApp.submitEvidenceWithSignatureEnhanced(
                evidenceID,
                title,
                cid,
                fileMimeType,
                req.session.user.address,
                signature,           // The actual signature string
                dataHash,            // The data hash
                selectedAlgorithm,
                publicKey            // The public key for verification
            );
            console.log('✅ Used enhanced chaincode method');
        } catch (enhancedError) {
            console.log('⚠️ Enhanced method not available, using original method');
            result = await clientApp.submitEvidenceWithSignature(
                evidenceID,
                title,
                cid,
                fileMimeType,
                req.session.user.address,
                signature,
                dataHash
            );
        }

        console.log('✅ Blockchain submission result:', result);
        console.log('📁 ========== END UPLOAD DEBUG ==========\n');

        // Clean up temporary file
        fs.unlinkSync(filePath);

        // Performance Metrics Recording
        const totalUploadTime = Date.now() - uploadStartTime;
        recordEvidenceUpload('success', selectedAlgorithm);
        recordBlockchainTransaction('submit');
        
        // Update real-time metrics
        const io = req.app.get('io');
        const realtimeMetrics = req.app.get('realtimeMetrics');
        
        const currentVerificationTime = realtimeMetrics.lastSignatureVerificationTime || 0;
        
        // Update basic metrics
        realtimeMetrics.evidenceUploads++;
        realtimeMetrics.totalTransactions++;
        realtimeMetrics.averageLatency = (realtimeMetrics.averageLatency * (realtimeMetrics.totalTransactions - 1) + totalUploadTime / 1000) / realtimeMetrics.totalTransactions;
        
        // Update crypto times
        realtimeMetrics.lastSignatureCreationTime = signatureCreationTime;
        realtimeMetrics.lastSignatureVerificationTime = currentVerificationTime;
        realtimeMetrics.lastAlgorithmUsed = selectedAlgorithm;
        
        io.emit('metrics-update', realtimeMetrics);
        
        console.log(`📊 Performance Metrics - Upload: ${totalUploadTime}ms, ${selectedAlgorithm} Signature: ${signatureCreationTime}ms`);

        res.render('success', {
            title: 'Upload Successful - Evidence Management System',
            user: req.session.user,
            message: `Evidence uploaded and digitally signed using ${selectedAlgorithm}! CID: ${cid}`,
            result: result,
            evidenceId: evidenceID,
            signature: signature,
            algorithm: selectedAlgorithm,
            signatureSize: signature.length,
            creationTime: signatureCreationTime
        });
    } catch (error) {
        console.error("❌ Error during file upload:", error);
        
        recordEvidenceUpload('error');
        
        // Clean up file on error
        if (req.file && req.file.path) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (cleanupError) {
                console.log('⚠️ Could not clean up temporary file:', cleanupError.message);
            }
        }
        
        res.render('error', {
            title: 'Upload Failed - Evidence Management System',
            user: req.session.user,
            message: "File upload failed",
            error: error.message
        });
    }
});

// 🔽 ENHANCED: Signature verification with algorithm support 🔽
router.get('/evidence/:id/verify', requireAuth, async (req, res) => {
    const verifyStartTime = Date.now();
    let verificationStartTime;

    try {
        const { id } = req.params;
        const { algorithm } = req.query; // Optional algorithm parameter
        
        console.log(`\n🔍 ========== SIGNATURE VERIFICATION DEBUG ==========`);
        console.log(`🔍 Starting signature verification for evidence: ${id}`);
        if (algorithm) console.log(`🔍 Requested verification algorithm: ${algorithm}`);
        
        // Get evidence details
        const evidence = await clientApp.readEvidence(id);
        console.log('📄 Evidence retrieved from blockchain:');
        console.log('  - ID:', evidence.evidenceId);
        console.log('  - Title:', evidence.title);
        console.log('  - CID:', evidence.cid);
        console.log('  - Uploader:', evidence.uploaderAddress);
        console.log('  - Algorithm:', evidence.signatureAlgorithm || 'ECC');
        console.log('  - Has Signature:', !!evidence.signature);
        console.log('  - Has Data Hash:', !!evidence.signedDataHash);
        
        if (!evidence.signature) {
            console.log('❌ No signature found on evidence');
            return res.render('signatureVerification', {
                title: 'Signature Verification - Evidence Management System',
                user: req.session.user,
                evidence: evidence,
                verificationResult: { valid: false, error: 'No digital signature found on this evidence' },
                isValid: false
            });
        }

        if (!evidence.signedDataHash) {
            console.log('❌ No data hash found on evidence');
            return res.render('signatureVerification', {
                title: 'Signature Verification - Evidence Management System',
                user: req.session.user,
                evidence: evidence,
                verificationResult: { valid: false, error: 'No data hash found on this evidence' },
                isValid: false
            });
        }

        // Get uploader's public key
        let uploaderPublicKey;
        try {
            const uploader = await clientApp.getUser(evidence.uploaderAddress);
            uploaderPublicKey = uploader.publicKey;
            console.log('🔑 Uploader public key retrieved successfully');
            console.log('  - Uploader Name:', uploader.name);
            console.log('  - Public Key (first 32 chars):', uploaderPublicKey.substring(0, 32) + '...');
        } catch (userError) {
            console.log('❌ Could not retrieve uploader:', userError.message);
            return res.render('signatureVerification', {
                title: 'Signature Verification - Evidence Management System',
                user: req.session.user,
                evidence: evidence,
                verificationResult: { valid: false, error: 'Could not retrieve uploader information from blockchain' },
                isValid: false
            });
        }

        // Reconstruct the exact data that should have been signed
        const signedData = {
            evidenceID: evidence.evidenceId,
            title: evidence.title,
            cid: evidence.cid,
            mimeType: evidence.mimeType,
            uploaderAddress: evidence.uploaderAddress,
            algorithm: evidence.signatureAlgorithm || 'ECC'
        };

        console.log('📝 Data being used for verification:');
        console.log(JSON.stringify(signedData, null, 2));
        
        console.log('🔐 Signature details:');
        console.log('  - Original Algorithm:', evidence.signatureAlgorithm || 'ECC');
        console.log('  - Signature:', evidence.signature.substring(0, 64) + '...');
        console.log('  - Stored Data Hash:', evidence.signedDataHash);
        
        // Calculate what the data hash SHOULD be
        const evidenceString = JSON.stringify(signedData);
        const calculatedHash = crypto.createHash('sha256').update(evidenceString).digest('hex');
        console.log('  - Calculated Data Hash:', calculatedHash);
        
        const hashMatches = (calculatedHash === evidence.signedDataHash);
        console.log('  - Hash Match:', hashMatches ? '✅ YES' : '❌ NO');
        
        if (!hashMatches) {
            console.log('❌ DATA HASH MISMATCH!');
            console.log('  Expected:', evidence.signedDataHash);
            console.log('  Actual:  ', calculatedHash);
        }

        // Verify signature using userManager with proper algorithm support
        console.log('🔍 Calling userManager verification...');
        
        verificationStartTime = Date.now();

        const verificationAlgorithm = evidence.signatureAlgorithm || 'ECC';
        let verificationResult;

        if (verificationAlgorithm === 'ECC') {
            verificationResult = await userManager.verifyEvidenceSignature(
                uploaderPublicKey,
                signedData,
                evidence.signature
            );
        } else {
            verificationResult = await userManager.verifyEvidenceSignature(
                uploaderPublicKey,
                signedData,
                evidence.signature,
                verificationAlgorithm
            );
        }

        const verificationTime = Date.now() - verificationStartTime;
        recordSignatureVerification(verificationAlgorithm, verificationTime, verificationResult === true);
        recordBlockchainTransaction('verify');
        console.log(`⏱️ ${verificationAlgorithm} signature verification time: ${verificationTime}ms`);

        console.log('✅ UserManager verification result:', verificationResult);
        console.log('🔍 ========== END VERIFICATION DEBUG ==========\n');

        // Real-time Metrics Update
        const totalVerificationTime = Date.now() - verifyStartTime;
        const io = req.app.get('io');
        const realtimeMetrics = req.app.get('realtimeMetrics');
        
        const currentCreationTime = realtimeMetrics.lastSignatureCreationTime || 0;
        
        realtimeMetrics.signatureVerifications++;
        realtimeMetrics.totalTransactions++;
        realtimeMetrics.averageLatency = (realtimeMetrics.averageLatency * (realtimeMetrics.totalTransactions - 1) + totalVerificationTime / 1000) / realtimeMetrics.totalTransactions;
        
        realtimeMetrics.lastSignatureCreationTime = currentCreationTime;
        realtimeMetrics.lastSignatureVerificationTime = verificationTime;
        realtimeMetrics.lastAlgorithmUsed = verificationAlgorithm;
        
        io.emit('metrics-update', realtimeMetrics);
        console.log(`📊 Performance Metrics - Total Verification: ${totalVerificationTime}ms, ${verificationAlgorithm} Crypto Verification: ${verificationTime}ms`);

        res.render('signatureVerification', {
            title: 'Signature Verification - Evidence Management System',
            user: req.session.user,
            evidence: evidence,
            verificationResult: verificationResult,
            isValid: verificationResult === true,
            signedData: signedData,
            uploaderPublicKey: uploaderPublicKey,
            hashMatches: hashMatches,
            calculatedHash: calculatedHash,
            algorithm: verificationAlgorithm,
            verificationTime: verificationTime
        });
    } catch (error) {
        console.error("❌ Error verifying signature:", error);
        
        recordSignatureVerificationCount('error');
        
        res.render('error', {
            title: 'Verification Failed - Evidence Management System',
            user: req.session.user,
            message: "Failed to verify digital signature",
            error: error.message
        });
    }
});

// 🔽 ENHANCED: List all evidence with algorithm filtering 🔽
router.get('/list', requireAuth, async (req, res) => {
    try {
        const { algorithm, page = 1, limit = 10 } = req.query;
        const evidenceList = await clientApp.getAllEvidence();
        
        // Filter by algorithm if specified
        let filteredEvidence = evidenceList;
        if (algorithm && algorithm !== 'ALL') {
            filteredEvidence = evidenceList.filter(evidence => 
                (evidence.signatureAlgorithm || 'ECC') === algorithm
            );
        }

        // Algorithm statistics
        const algorithmStats = {};
        evidenceList.forEach(evidence => {
            const algo = evidence.signatureAlgorithm || 'ECC';
            algorithmStats[algo] = (algorithmStats[algo] || 0) + 1;
        });

        // Pagination
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;
        const paginatedEvidence = filteredEvidence.slice(startIndex, endIndex);

        res.render('listEvidence', {
            title: 'All Evidence - Evidence Management System',
            user: req.session.user,
            evidenceList: paginatedEvidence,
            currentTime: new Date().toLocaleString(),
            algorithm: algorithm,
            algorithmStats: algorithmStats,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(filteredEvidence.length / limit),
                totalEvidence: filteredEvidence.length,
                hasNext: endIndex < filteredEvidence.length,
                hasPrev: startIndex > 0
            },
            supportedAlgorithms: userManager.getSupportedAlgorithms()
        });
    } catch (error) {
        console.error("❌ Error fetching evidence list:", error);
        res.render('error', {
            title: 'Error - Evidence Management System',
            user: req.session.user,
            message: "Failed to fetch evidence list",
            error: error.message
        });
    }
});

// Transfer evidence page
router.get('/evidence/:id/transfer', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        const evidence = await clientApp.readEvidence(id);
        
        res.render('transferEvidence', {
            title: 'Transfer Evidence - Evidence Management System',
            user: req.session.user,
            evidence: evidence
        });
    } catch (error) {
        console.error("❌ Error fetching evidence for transfer:", error);
        res.render('error', {
            title: 'Error - Evidence Management System',
            user: req.session.user,
            message: "Failed to fetch evidence for transfer",
            error: error.message
        });
    }
});

// Handle evidence transfer
router.post('/evidence/:id/transfer', requireAuth, async (req, res) => {
    const transferStartTime = Date.now();

    try {
        const { id } = req.params;
        const { newOwner } = req.body;

        console.log(`🔄 Transferring evidence ${id} to ${newOwner}`);

        if (!newOwner) {
            throw new Error('New owner is required');
        }

        const result = await clientApp.transferEvidenceOwnership(id, newOwner);
        
        console.log('✅ Transfer successful:', result);

        const transferTime = Date.now() - transferStartTime;
        recordOwnershipTransfer('success');
        recordBlockchainTransaction('transfer');
        
        const io = req.app.get('io');
        const realtimeMetrics = req.app.get('realtimeMetrics');
        
        const currentCreationTime = realtimeMetrics.lastSignatureCreationTime || 0;
        const currentVerificationTime = realtimeMetrics.lastSignatureVerificationTime || 0;
        
        realtimeMetrics.totalTransactions++;
        realtimeMetrics.averageLatency = (realtimeMetrics.averageLatency * (realtimeMetrics.totalTransactions - 1) + transferTime / 1000) / realtimeMetrics.totalTransactions;
        
        realtimeMetrics.lastSignatureCreationTime = currentCreationTime;
        realtimeMetrics.lastSignatureVerificationTime = currentVerificationTime;
        
        io.emit('metrics-update', realtimeMetrics);
        console.log(`📊 Performance Metrics - Transfer: ${transferTime}ms`);
        console.log('📈 Emitting metrics update to dashboard');      

        res.render('success', {
            title: 'Transfer Successful - Evidence Management System',
            user: req.session.user,
            message: `Evidence ownership transferred successfully to ${newOwner}!`,
            result: result,
            evidenceId: id
        });
    } catch (error) {
        console.error("❌ Error transferring evidence:", error);
        
        recordOwnershipTransfer('error');

        let errorMessage = "Failed to transfer evidence ownership";
        if (error.message.includes('already exists')) {
            errorMessage = "Evidence with this ID already exists";
        } else if (error.message.includes('not found')) {
            errorMessage = "Evidence not found";
        } else if (error.message.includes('access denied')) {
            errorMessage = "You don't have permission to transfer this evidence";
        }

        res.render('error', {
            title: 'Transfer Failed - Evidence Management System',
            user: req.session.user,
            message: errorMessage,
            error: error.message
        });
    }
});

// View evidence by owner
router.get('/evidence/owner/:ownerId', requireAuth, async (req, res) => {
    try {
        const { ownerId } = req.params;
        
        const evidenceList = await clientApp.getEvidenceByOwner(ownerId);
        
        res.render('evidenceByOwner', {
            title: `Evidence for ${ownerId} - Evidence Management System`,
            user: req.session.user,
            evidenceList: evidenceList,
            ownerId: ownerId
        });
    } catch (error) {
        console.error("❌ Error fetching evidence by owner:", error);
        res.render('error', {
            title: 'Error - Evidence Management System',
            user: req.session.user,
            message: "Failed to fetch evidence by owner",
            error: error.message
        });
    }
});

// Direct file download from local IPFS node
router.get('/download/:cid', requireAuth, async (req, res) => {
    let cid = req.params.cid;
    
    try {
        console.log(`📥 Starting direct download for CID: ${cid}`);
        
        let filename = `evidence-${cid}`;
        let contentType = 'application/octet-stream';
        let evidenceTitle = 'Unknown';
        
        try {
            const allEvidence = await clientApp.getAllEvidence();
            const evidence = allEvidence.find(e => e.cid === cid);
            
            if (evidence) {
                evidenceTitle = evidence.title;
                filename = `evidence-${evidence.evidenceId}-${evidence.title.replace(/[^a-zA-Z0-9]/g, '_')}`;
                contentType = evidence.mimeType || contentType;
                
                const extMap = {
                    'image/jpeg': '.jpg',
                    'image/jpg': '.jpg',
                    'image/png': '.png',
                    'application/pdf': '.pdf',
                    'application/msword': '.doc',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                    'text/plain': '.txt'
                };
                
                if (evidence.mimeType && extMap[evidence.mimeType]) {
                    filename += extMap[evidence.mimeType];
                } else {
                    filename += '.bin';
                }
                
                console.log(`📄 Evidence details: "${evidenceTitle}" -> ${filename} (${contentType})`);
            }
        } catch (e) {
            console.log('⚠️ Could not get evidence details, using default filename');
        }
        
        console.log(`🔍 Retrieving evidence from local IPFS...`);
        let fileBuffer;
        let envelope = null;
        try {
            envelope = await evidenceEncryption.fetchEnvelope(ipfs, cid);
        } catch (e) {
            envelope = null;   // evidence uploaded before encryption was introduced
        }
        if (envelope) {
            const outPath = path.join('uploads', `dl-${crypto.randomBytes(6).toString('hex')}`);
            try {
                await evidenceEncryption.retrieveDecryptedEvidence(ipfs, cid, outPath, {
                    recipient: EVIDENCE_ORG,
                    kemSecretKey: evidenceEncryption.loadSecretKey(EVIDENCE_ORG)
                });
                fileBuffer = fs.readFileSync(outPath);
            } finally {
                fs.rmSync(outPath, { force: true });
            }
            console.log(`✅ Decrypted evidence for ${EVIDENCE_ORG}: ${fileBuffer.length} bytes, SHA-256 verified`);
        } else {
            const fileChunks = [];
            for await (const chunk of ipfs.cat(cid)) fileChunks.push(chunk);
            fileBuffer = Buffer.concat(fileChunks);
            res.setHeader('X-Evidence-Encryption', 'none (pre-revision plaintext upload)');
            console.log(`⚠️ Legacy plaintext evidence: ${fileBuffer.length} bytes`);
        }
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Length', fileBuffer.length);
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('X-Evidence-Title', evidenceTitle);
        
        console.log(`🚀 Serving file: ${filename} (${fileBuffer.length} bytes)`);
        res.send(fileBuffer);
        
    } catch (error) {
        console.error("❌ Direct download failed:", error.message);
        
        if (error.message.includes('no link named')) {
            res.render('error', {
                title: 'Download Failed - Evidence Management System',
                user: req.session.user,
                message: "File not found in IPFS",
                error: `The evidence file with CID ${cid} is not available in the local IPFS node.`
            });
        } else {
            res.render('error', {
                title: 'Download Failed - Evidence Management System',
                user: req.session.user,
                message: "Download failed",
                error: error.message
            });
        }
    }
});

// View specific evidence details
router.get('/evidence/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const evidence = await clientApp.readEvidence(id);
        
        res.render('readEvidence', {
            title: `Evidence ${id} - Evidence Management System`,
            user: req.session.user,
            evidence: evidence
        });
    } catch (error) {
        console.error("❌ Error fetching evidence:", error);
        res.render('error', {
            title: 'Error - Evidence Management System',
            user: req.session.user,
            message: "Failed to fetch evidence",
            error: error.message
        });
    }
});

// Update evidence status
router.post('/evidence/:id/status', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, additionalInfo } = req.body;

        const result = await clientApp.updateEvidence(
            id,
            status,
            additionalInfo || "No additional info"
        );

        res.render('success', {
            title: 'Status Updated - Evidence Management System',
            user: req.session.user,
            message: `Evidence status updated successfully!`,
            result: result
        });
    } catch (error) {
        console.error("❌ Error updating evidence status:", error);
        res.render('error', {
            title: 'Update Failed - Evidence Management System',
            user: req.session.user,
            message: "Failed to update evidence status",
            error: error.message
        });
    }
});

// 🔽 ENHANCED: Performance Dashboard with PQC Metrics 🔽
router.get('/performance', requireAuth, (req, res) => {
    res.render('performanceDashboard', {
        title: 'Performance Dashboard - Evidence Management System',
        user: req.session.user,
        supportedAlgorithms: userManager.getSupportedAlgorithms()
    });
});

// Debug metrics endpoint
router.get('/debug-metrics', requireAuth, async (req, res) => {
    try {
        const { promClient } = require('../utils/cryptoPerformanceMonitor');
        const metrics = await promClient.register.getMetricsAsJSON();
        
        const cryptoMetrics = metrics.filter(metric => 
            metric.name.includes('crypto_') || 
            metric.name.includes('signature_') ||
            metric.name.includes('evidence_')
        );
        
        console.log('📊 Current Crypto Metrics:');
        cryptoMetrics.forEach(metric => {
            console.log(`  ${metric.name}:`, metric.values || 'No data');
        });
        
        res.json(cryptoMetrics);
    } catch (error) {
        console.error('Debug metrics error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug current metrics endpoint
router.get('/debug-current-metrics', (req, res) => {
    try {
        const realtimeMetrics = req.app.get('realtimeMetrics');
        
        res.json({
            realtimeMetrics: realtimeMetrics,
            cryptoTimes: {
                creation: realtimeMetrics.lastSignatureCreationTime,
                verification: realtimeMetrics.lastSignatureVerificationTime,
                algorithm: realtimeMetrics.lastAlgorithmUsed
            }
        });
    } catch (error) {
        console.error('Debug current metrics error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add to evidenceRoutes.js - Temporary debug route
router.get('/debug-transfer-metrics', (req, res) => {
    const realtimeMetrics = req.app.get('realtimeMetrics');
    const io = req.app.get('io');
    
    console.log('=== DEBUG TRANSFER METRICS ===');
    console.log('Before update:', JSON.stringify(realtimeMetrics, null, 2));
    
    realtimeMetrics.totalTransactions++;
    realtimeMetrics.averageLatency = (realtimeMetrics.averageLatency * (realtimeMetrics.totalTransactions - 1) + 2.5) / realtimeMetrics.totalTransactions;
    
    console.log('After update:', JSON.stringify(realtimeMetrics, null, 2));
    
    io.emit('metrics-update', realtimeMetrics);
    console.log('Metrics update emitted');
    
    res.json({
        message: 'Transfer metrics debug completed',
        metrics: realtimeMetrics
    });
});

module.exports = router;