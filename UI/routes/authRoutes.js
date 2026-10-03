const express = require('express');
const UserManager = require('../utils/userManager');
const { ClientApplication } = require('../../Client/client');

// 🔽 ADD PERFORMANCE MONITORING IMPORTS 🔽
const { 
    recordUserRegistration, 
    recordBlockchainTransaction,
    recordKeyGeneration 
} = require('../utils/cryptoPerformanceMonitor');
// 🔼 END OF ADDITION 🔼

const router = express.Router();

const userManager = new UserManager();
const clientApp = new ClientApplication();

// Registration page
router.get('/register', (req, res) => {
    res.render('register', { 
        title: 'Register - Evidence Management System',
        message: null,
        keys: null,
        formData: null,
        supportedAlgorithms: userManager.getSupportedAlgorithms(),
        selectedAlgorithm: 'DILITHIUM3'
    });
});

// Generate keys endpoint - UPDATED WITH PQC SUPPORT
router.post('/generate-keys', async (req, res) => {
    const { name, email, algorithm = 'DILITHIUM3' } = req.body;
    
    try {
        // Validate inputs
        if (!name || !email) {
            return res.render('register', {
                title: 'Register - Evidence Management System',
                message: 'Name and email are required',
                keys: null,
                formData: { name, email },
                supportedAlgorithms: userManager.getSupportedAlgorithms(),
                selectedAlgorithm: algorithm
            });
        }

        // 🔽 UPDATED: PQC Key Generation with Algorithm Selection 🔽
        const keyGenStartTime = Date.now();
        const keyPair = await userManager.generateKeyPair(algorithm);
        const keyGenTime = Date.now() - keyGenStartTime;
        
        recordKeyGeneration(algorithm, keyGenTime, {
            publicKeySize: keyPair.keySize?.public || 0,
            privateKeySize: keyPair.keySize?.private || 0
        });
        
        console.log(`⏱️ ${algorithm} key generation time: ${keyGenTime}ms`);
        console.log(`🔑 ${algorithm} Key Sizes - Public: ${keyPair.keySize?.public} bytes, Private: ${keyPair.keySize?.private} bytes`);
        // 🔼 END OF UPDATE 🔼

        res.render('register', {
            title: 'Register - Evidence Management System',
            message: `${algorithm} keys generated successfully! Save your private key securely.`,
            keys: keyPair,
            formData: { name, email },
            supportedAlgorithms: userManager.getSupportedAlgorithms(),
            selectedAlgorithm: algorithm,
            keyDetails: {
                algorithm: algorithm,
                generationTime: keyGenTime,
                publicKeySize: keyPair.keySize?.public || 'N/A',
                privateKeySize: keyPair.keySize?.private || 'N/A',
                securityLevel: userManager.getAlgorithmDetails(algorithm)?.security || 128
            }
        });
    } catch (error) {
        console.error('Error generating keys:', error);
        res.render('register', {
            title: 'Register - Evidence Management System',
            message: 'Error generating keys: ' + error.message,
            keys: null,
            formData: { name, email },
            supportedAlgorithms: userManager.getSupportedAlgorithms(),
            selectedAlgorithm: 'DILITHIUM3'
        });
    }
});

// Complete registration - UPDATED WITH ALGORITHM SUPPORT
router.post('/register', async (req, res) => {
    const { name, email, publicKey, privateKey, address, algorithm = 'DILITHIUM3' } = req.body;
    
    // 🔽 ADD REGISTRATION PERFORMANCE TRACKING 🔽
    const registrationStartTime = Date.now();
    // 🔼 END OF ADDITION 🔼
    
    try {
        // Validate all required fields
        if (!name || !email || !publicKey || !privateKey || !address) {
            return res.render('register', {
                title: 'Register - Evidence Management System',
                message: 'All fields are required',
                keys: { publicKey, privateKey, address },
                formData: { name, email },
                supportedAlgorithms: userManager.getSupportedAlgorithms(),
                selectedAlgorithm: algorithm
            });
        }

        // ✅ Validate private key format before registration
        if (!userManager.isValidPrivateKey(privateKey)) {
            return res.render('register', {
                title: 'Register - Evidence Management System',
                message: 'Invalid private key format. Please generate keys again.',
                keys: { publicKey, privateKey, address },
                formData: { name, email },
                supportedAlgorithms: userManager.getSupportedAlgorithms(),
                selectedAlgorithm: algorithm
            });
        }

        // Register user in local database with algorithm
        const user = userManager.registerUser(name, email, publicKey, privateKey, address, algorithm);
        
        // ✅ REPLACED: Blockchain registration with enhanced method and fallback
        let blockchainSuccess = false;
        try {
            const createdAt = new Date().toISOString();
            
            // Use enhanced registration method if available
            let blockchainResult;
            try {
                blockchainResult = await clientApp.registerUserEnhanced(name, email, publicKey, address, createdAt, algorithm);
                console.log('✅ User registered on blockchain with enhanced method:', blockchainResult);
            } catch (enhancedError) {
                // Fallback to original method
                console.log('⚠️ Enhanced registration not available, using original method');
                blockchainResult = await clientApp.registerUser(name, email, publicKey, address, createdAt);
            }
            
            blockchainSuccess = true;
        } catch (blockchainError) {
            console.error('❌ Blockchain registration failed:', blockchainError);
            // Continue with local registration even if blockchain fails
            console.log('⚠️ User registered locally but blockchain registration failed');
        }
        
        // 🔽 ADD REGISTRATION METRICS TRACKING 🔽
        const registrationTime = Date.now() - registrationStartTime;
        if (blockchainSuccess) {
            recordUserRegistration('success', algorithm);
            recordBlockchainTransaction('register');
            
            // Update real-time metrics
            const io = req.app.get('io');
            const realtimeMetrics = req.app.get('realtimeMetrics');
            realtimeMetrics.userRegistrations++;
            realtimeMetrics.totalTransactions++;
            realtimeMetrics.averageLatency = (realtimeMetrics.averageLatency * (realtimeMetrics.totalTransactions - 1) + registrationTime / 1000) / realtimeMetrics.totalTransactions;
            realtimeMetrics.lastAlgorithmUsed = algorithm;
            
            io.emit('metrics-update', realtimeMetrics);
            console.log(`📊 Performance Metrics - ${algorithm} Registration: ${registrationTime}ms`);
        } else {
            recordUserRegistration('error');
        }
        // 🔼 END OF ADDITION 🔼

        // Set success message in session and redirect to login
        req.session.registrationSuccess = `Registration successful with ${algorithm}! Please login with your private key. Your address: ${address}`;
        res.redirect('/login');
        
    } catch (error) {
        console.error('Registration error:', error);
        
        // 🔽 ADD ERROR METRICS TRACKING 🔽
        recordUserRegistration('error');
        // 🔼 END OF ADDITION 🔼

        res.render('register', {
            title: 'Register - Evidence Management System',
            message: 'Registration failed: ' + error.message,
            keys: { publicKey, privateKey, address },
            formData: { name, email },
            supportedAlgorithms: userManager.getSupportedAlgorithms(),
            selectedAlgorithm: algorithm
        });
    }
});

// Login page
router.get('/login', (req, res) => {
    const registrationSuccess = req.session.registrationSuccess;
    
    // Clear the session message after displaying it
    if (req.session.registrationSuccess) {
        delete req.session.registrationSuccess;
    }
    
    res.render('login', { 
        title: 'Login - Evidence Management System',
        message: null,
        registrationSuccess: registrationSuccess
    });
});

// ✅ FIXED: Login endpoint - made async
router.post('/login', async (req, res) => {
    const { privateKey } = req.body;
    
    try {
        if (!privateKey) {
            return res.render('login', {
                title: 'Login - Evidence Management System',
                message: 'Private key is required',
                registrationSuccess: null
            });
        }

        // ✅ Validate private key format before login attempt
        if (!userManager.isValidPrivateKey(privateKey)) {
            return res.render('login', {
                title: 'Login - Evidence Management System',
                message: 'Invalid private key format. Please check your private key.',
                registrationSuccess: null
            });
        }

        const user = userManager.loginUser(privateKey);
        
        // ✅ FIXED: Verify user exists on blockchain (optional check)
        try {
            const blockchainUser = await clientApp.getUser(user.address);
            console.log('✅ User verified on blockchain:', blockchainUser.name);
            user.blockchainVerified = true;
        } catch (blockchainError) {
            console.log('⚠️ User not found on blockchain, but local login successful');
            user.blockchainVerified = false;
        }
        
        req.session.user = user;
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', {
            title: 'Login - Evidence Management System',
            message: 'Login failed: ' + error.message,
            registrationSuccess: null
        });
    }
});

// Logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// Profile page (optional - for viewing user details)
router.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    res.render('profile', {
        title: 'Profile - Evidence Management System',
        user: req.session.user
    });
});

// ✅ Test digital signature route (for development/testing)
router.get('/test-signature', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    res.render('testSignature', {
        title: 'Test Digital Signature - Evidence Management System',
        user: req.session.user,
        message: null,
        signatureResult: null
    });
});

// ✅ Test signature creation - UPDATED WITH PQC SUPPORT
router.post('/test-signature', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    const { testData, algorithm = 'DILITHIUM3' } = req.body;
    
    try {
        if (!testData) {
            return res.render('testSignature', {
                title: 'Test Digital Signature - Evidence Management System',
                user: req.session.user,
                message: 'Test data is required',
                signatureResult: null
            });
        }

        // Create signature using user's private key with selected algorithm
        let signature;
        if (algorithm === 'ECC') {
            signature = userManager.createSignature(req.session.user.privateKey, testData);
        } else {
            signature = await userManager.createSignature(req.session.user.privateKey, testData, algorithm);
        }
        
        // Verify the signature
        let isValid;
        if (algorithm === 'ECC') {
            isValid = userManager.verifySignature(
                req.session.user.publicKey, 
                testData, 
                signature.signature
            );
        } else {
            const verificationResult = await userManager.verifySignature(
                req.session.user.publicKey, 
                testData, 
                signature.signature,
                algorithm
            );
            isValid = verificationResult.isValid;
        }

        res.render('testSignature', {
            title: 'Test Digital Signature - Evidence Management System',
            user: req.session.user,
            message: `${algorithm} signature test completed successfully!`,
            signatureResult: {
                originalData: testData,
                signature: signature.signature,
                dataHash: signature.dataHash,
                publicKey: signature.publicKey,
                timestamp: signature.timestamp,
                algorithm: algorithm,
                isValid: isValid,
                verificationMessage: isValid ? '✅ Signature is valid' : '❌ Signature is invalid',
                signatureSize: signature.signatureSize,
                performance: signature.performance
            },
            supportedAlgorithms: userManager.getSupportedAlgorithms(),
            selectedAlgorithm: algorithm
        });
    } catch (error) {
        console.error('Signature test error:', error);
        res.render('testSignature', {
            title: 'Test Digital Signature - Evidence Management System',
            user: req.session.user,
            message: 'Signature test failed: ' + error.message,
            signatureResult: null,
            supportedAlgorithms: userManager.getSupportedAlgorithms(),
            selectedAlgorithm: 'DILITHIUM3'
        });
    }
});

// ✅ Get all users from blockchain (admin feature)
router.get('/users', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    try {
        const users = await clientApp.getAllUsers();
        
        res.render('users', {
            title: 'Registered Users - Evidence Management System',
            user: req.session.user,
            users: users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.render('users', {
            title: 'Registered Users - Evidence Management System',
            user: req.session.user,
            users: [],
            error: error.message
        });
    }
});

// ✅ Check if user exists on blockchain
router.get('/check-user/:address', async (req, res) => {
    if (!req.session.user) {
        return res.json({ error: 'Not authenticated' });
    }
    
    try {
        const { address } = req.params;
        const userExists = await clientApp.userExists(address);
        
        res.json({ 
            exists: userExists,
            address: address
        });
    } catch (error) {
        console.error('Error checking user:', error);
        res.json({ 
            error: error.message,
            address: req.params.address
        });
    }
});

// =============================================================================
// TEMPORARY ADMIN ROUTES FOR DATABASE CLEANUP - REMOVE AFTER USE
// =============================================================================

// Method 4: Direct File Deletion (Most Effective)
// router.get('/reset-database', (req, res) => {
//     try {
//         const fs = require('fs');
//         const path = require('path');
        
//         // Path to your users.json file - adjust based on your actual path
//         // Common locations:
//         const possiblePaths = [
//             path.join(__dirname, '../data/users.json'),
//             path.join(__dirname, './data/users.json'),
//             path.join(__dirname, '../../data/users.json'),
//             path.join(__dirname, 'users.json')
//         ];
        
//         let usersFilePath;
//         for (const filePath of possiblePaths) {
//             if (fs.existsSync(filePath)) {
//                 usersFilePath = filePath;
//                 console.log(`📁 Found users database at: ${usersFilePath}`);
//                 break;
//             }
//         }
        
//         if (!usersFilePath) {
//             return res.json({ 
//                 success: false, 
//                 message: 'User database file not found in any common locations' 
//             });
//         }
        
//         // Backup the file
//         const backupPath = usersFilePath + '.backup-' + Date.now();
//         fs.copyFileSync(usersFilePath, backupPath);
//         console.log(`📁 Backup created: ${backupPath}`);
        
//         // Create empty users array
//         const emptyUsers = [];
//         fs.writeFileSync(usersFilePath, JSON.stringify(emptyUsers, null, 2));
        
//         console.log('✅ User database reset successfully');
//         res.json({ 
//             success: true, 
//             message: 'User database reset successfully. All users deleted.',
//             backup: backupPath,
//             originalFile: usersFilePath
//         });
        
//     } catch (error) {
//         console.error('Reset database error:', error);
//         res.status(500).json({ error: error.message });
//     }
// });

// // Method to view current users (for verification)
// router.get('/view-users', (req, res) => {
//     try {
//         const userManager = new UserManager();
//         const currentUsers = userManager.getAllUsers();
        
//         res.json({
//             totalUsers: currentUsers.length,
//             users: currentUsers.map(u => ({
//                 email: u.email,
//                 name: u.name,
//                 address: u.address,
//                 publicKey: u.publicKey ? u.publicKey.substring(0, 32) + '...' : 'N/A',
//                 algorithm: u.algorithm || 'ECC'
//             }))
//         });
//     } catch (error) {
//         console.error('View users error:', error);
//         res.status(500).json({ error: error.message });
//     }
// });

// =============================================================================
// END OF TEMPORARY ROUTES
// =============================================================================

module.exports = router;
// Add this to your existing authRoutes.js

// Add role to registration page
router.get('/register', (req, res) => {
    res.render('register', { 
        title: 'Register - Evidence Management System',
        message: null,
        keys: null,
        formData: null,
        supportedAlgorithms: userManager.getSupportedAlgorithms(),
        selectedAlgorithm: 'DILITHIUM3',
        roles: ['police_officer', 'court_judge']  // Add roles
    });
});

// Update registration to include role
// Modify your existing register POST route to include role
// Add 'role' field to the user object
