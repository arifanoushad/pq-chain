const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const http = require('http');
const app = express();

const socketIo = require('socket.io');

// Import the routes
const evidenceRoutes = require('./routes/evidenceRoutes');
const authRoutes = require('./routes/authRoutes');
const committeeRoutes = require('./routes/committeeRoutes');
// 🔽 CORRECT: Modern express-handlebars import for v8.x
const expressHandlebars = require('express-handlebars');

// Create HTTP server for Socket.IO
const server = http.createServer(app);

// Initialize Socket.IO
const io = socketIo(server);

// 🔽 CORRECT: Configure express-handlebars for v8.x
const hbs = expressHandlebars.create({
    extname: '.hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views/layouts'),
    partialsDir: path.join(__dirname, 'views/partials'),
    helpers: {
        // Equality helper
        eq: function (a, b) {
            return a === b;
        },
        // OR logical helper
        or: function (a, b) {
            return a || b;
        },
        // Substring helper
        substr: function (str, start, len) {
            if (str && typeof str === 'string') {
                return str.substring(start, start + len);
            }
            return '';
        },
        // Date formatting helper
        formatDate: function(date) {
            if (!date) return 'N/A';
            return new Date(date).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },
        // Greater than helper
        gt: function (a, b) {
            return a > b;
        },
        // Less than helper
        lt: function (a, b) {
            return a < b;
        },
        // AND logical helper
        and: function (a, b) {
            return a && b;
        },
        // Not equal helper
        neq: function (a, b) {
            return a !== b;
        },
        // Convert to lowercase
        lowercase: function (str) {
            return str ? str.toLowerCase() : '';
        },
        // Convert to uppercase
        uppercase: function (str) {
            return str ? str.toUpperCase() : '';
        },
        // Check if value is in array
        inArray: function (value, array) {
            if (!Array.isArray(array)) return false;
            return array.includes(value);
        },
        // JSON stringify helper
        json: function (obj) {
            return JSON.stringify(obj);
        }
    }
});

// Set Handlebars as the view engine
app.engine('hbs', hbs.engine);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session middleware
app.use(session({
    secret: 'evidence-management-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Make user data available to all templates
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    res.locals.currentTime = new Date().toLocaleString();
    next();
});

// Initialize real-time metrics (for dashboard only)
const realtimeMetrics = {
    totalTransactions: 0,
    evidenceUploads: 0,
    signatureVerifications: 0,
    averageLatency: 0,
    activeSessions: 0,
    lastSignatureCreationTime: 0,
    lastSignatureVerificationTime: 0,
    userRegistrations: 0 
};

// Use the routes
app.use('/', evidenceRoutes);
app.use('/', authRoutes);
app.use('/', committeeRoutes);
// ===== TEST ROUTES =====
app.get('/test-layout', (req, res) => {
    res.render('test-layout', {
        title: 'Layout Test',
        user: { name: 'Test User' }
    });
});

// Test route for Handlebars helpers
app.get('/test-helpers', (req, res) => {
    res.render('test-helpers', {
        title: 'Handlebars Helpers Test',
        user: req.session.user || { name: 'Test User' },
        testData: {
            string: 'HelloWorld123456',
            ownerId: 'PoliceOrg',
            ownerId2: 'policeorg',
            status: 'Submitted',
            number1: 10,
            number2: 5,
            array: ['PoliceOrg', 'CourtOrg', 'ProsecutorOrg'],
            evidence: {
                evidenceId: 'EVD001',
                title: 'Test Evidence',
                ownerId: 'PoliceOrg',
                status: 'Submitted',
                cid: 'QmXyz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz',
                mimeType: 'image/jpeg',
                createdAt: new Date()
            }
        }
    });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('📊 Dashboard connected. Active sessions:', io.engine.clientsCount);
    
    // Update active sessions count
    realtimeMetrics.activeSessions = io.engine.clientsCount;
    
    // Send current metrics to newly connected client
    socket.emit('metrics-update', realtimeMetrics);
    
    socket.on('disconnect', () => {
        console.log('📊 Dashboard disconnected. Active sessions:', io.engine.clientsCount);
        realtimeMetrics.activeSessions = io.engine.clientsCount;
    });
    
    // Handle manual refresh requests
    socket.on('request-metrics-update', () => {
        socket.emit('metrics-update', realtimeMetrics);
    });
});

// Make Socket.io and metrics available to routes
app.set('io', io);
app.set('realtimeMetrics', realtimeMetrics);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).render('error', {
        title: 'Server Error - Evidence Management System',
        user: req.session.user,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Page Not Found - Evidence Management System',
        user: req.session.user,
        message: 'Page not found',
        error: 'The page you are looking for does not exist.'
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('🚀 Evidence Management System running on http://localhost:3000');
    console.log('📈 Real-time dashboard integrated');
    console.log('✅ Test the layout: http://localhost:3000/test-layout');
    console.log('✅ Test helpers: http://localhost:3000/test-helpers');
    console.log('✅ Evidence list: http://localhost:3000/list');
    console.log('✅ Dashboard: http://localhost:3000/dashboard');
    console.log('📊 Performance monitoring: Terminal output mode');
});