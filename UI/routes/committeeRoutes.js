// UI/routes/committeeRoutes.js
const express = require('express');
const router = express.Router();
const CommitteeManager = require('../utils/committeeManager');
const { ClientApplication } = require('../../Client/client');

const committeeManager = new CommitteeManager();
const clientApp = new ClientApplication();

const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

// List all committees
router.get('/committees', requireAuth, async (req, res) => {
    try {
        const committees = committeeManager.getAllCommittees();
        
        res.render('committees', {
            title: 'Committees - Evidence Management System',
            user: req.session.user,
            committees: committees,
            userCommittees: committeeManager.getUserCommittees(req.session.user.address)
        });
    } catch (error) {
        console.error('Error loading committees:', error);
        res.render('error', {
            title: 'Error',
            user: req.session.user,
            message: 'Failed to load committees',
            error: error.message
        });
    }
});

// Create committee page
router.get('/committees/create', requireAuth, async (req, res) => {
    try {
        const users = await clientApp.getAllUsers();
        
        res.render('createCommittee', {
            title: 'Create Committee',
            user: req.session.user,
            users: users,
            committeeTypes: ['police', 'court']
        });
    } catch (error) {
        console.error('Error:', error);
        res.render('error', {
            title: 'Error',
            user: req.session.user,
            message: 'Failed to load page',
            error: error.message
        });
    }
});

// Create committee submission
router.post('/committees/create', requireAuth, async (req, res) => {
    try {
        const { name, type, description, threshold, members } = req.body;
        
        const membersList = typeof members === 'string' ? JSON.parse(members) : members;
        
        const committeeData = {
            name: name,
            type: type,
            description: description,
            threshold: parseInt(threshold),
            members: membersList
        };
        
        const committee = await committeeManager.createCommittee(committeeData, req.session.user);
        
        req.session.successMessage = `Committee "${name}" created successfully!`;
        res.redirect('/committees');
        
    } catch (error) {
        console.error('Error:', error);
        res.render('createCommittee', {
            title: 'Create Committee',
            user: req.session.user,
            users: await clientApp.getAllUsers(),
            committeeTypes: ['police', 'court'],
            error: error.message,
            formData: req.body
        });
    }
});

// View committee details
router.get('/committees/:id', requireAuth, async (req, res) => {
    try {
        const committee = committeeManager.getCommittee(req.params.id);
        
        if (!committee) {
            return res.status(404).render('error', {
                title: 'Not Found',
                user: req.session.user,
                message: 'Committee not found',
                error: 'The requested committee does not exist'
            });
        }
        
        res.render('committeeDetails', {
            title: `${committee.name} - Committee Details`,
            user: req.session.user,
            committee: committee,
            isMember: committeeManager.isUserInCommittee(committee.id, req.session.user.address)
        });
    } catch (error) {
        console.error('Error:', error);
        res.render('error', {
            title: 'Error',
            user: req.session.user,
            message: 'Failed to load committee',
            error: error.message
        });
    }
});

// API endpoint for committee members
router.get('/api/committees/:id/members', requireAuth, async (req, res) => {
    try {
        const members = committeeManager.getCommitteeMembers(req.params.id);
        res.json({ success: true, members: members });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

module.exports = router;