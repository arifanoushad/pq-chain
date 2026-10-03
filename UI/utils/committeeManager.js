// UI/utils/committeeManager.js
const CommitteeModel = require('../models/Committee');
const { ClientApplication } = require('../../Client/client');
const secrets = require('secrets.js-grempe');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pqSeal = require('./pqSeal');

class CommitteeManager {
    /** @param {Object} [opts] - opts.dataDir overrides UI/data (tests) */
    constructor(opts = {}) {
        const dataDir = opts.dataDir || path.join(__dirname, '../data');
        this.model = new CommitteeModel(path.join(dataDir, 'committees.json'));
        this.sharesDir = path.join(dataDir, 'shares');
        this.clientApp = new ClientApplication();
    }

    async createCommittee(committeeData, sessionUser) {
        if (committeeData.threshold > committeeData.members.length) {
            throw new Error('Threshold cannot exceed number of members');
        }

        if (committeeData.threshold < 2) {
            throw new Error('Threshold must be at least 2');
        }

        // Skip blockchain verification for local testing
        console.log('⚠️ Skipping blockchain verification for local testing');

        // Create committee
        const committee = this.model.createCommittee({
            ...committeeData,
            createdBy: sessionUser.address
        });

        return committee;
    }

    // ─── Shamir share custody ──────────────────────────────────────────
    // Each member's share is sealed to that member's ML-KEM-768 public key
    // (utils/pqSeal.js) and stored in its own file,
    //   <dataDir>/shares/<committeeId>/<memberAddress>.json
    // The server never holds plaintext shares or member KEM secret keys.
    // Reconstruction takes shares submitted by at least t distinct members
    // and checks the result against a SHA-256 commitment of the secret.

    async generateCommitteeShares(committeeId, secret) {
        const committee = this.model.getCommitteeById(committeeId);
        if (!committee) {
            throw new Error(`Committee ${committeeId} not found`);
        }
        const missing = committee.members.filter(m => !m.kemPublicKey).map(m => m.address);
        if (missing.length) {
            throw new Error(`Members without an ML-KEM public key: ${missing.join(', ')}`);
        }

        const threshold = committee.threshold;
        const totalShares = committee.totalMembers;

        let secretHex;
        if (typeof secret === 'string' && /^[0-9a-fA-F]{64}$/.test(secret)) {
            secretHex = secret.toLowerCase();
        } else {
            // Hash to get 32 bytes hex
            secretHex = crypto.createHash('sha256').update(secret).digest('hex');
        }

        // Shares are strings in secrets.js format; share i goes to member i.
        const shares = secrets.share(secretHex, totalShares, threshold);

        const dir = path.join(this.sharesDir, committee.id);
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        for (let i = 0; i < committee.members.length; i++) {
            const member = committee.members[i];
            const record = {
                committeeId: committee.id,
                memberAddress: member.address,
                shareIndex: member.shareIndex,
                threshold,
                totalShares,
                sealed: await pqSeal.seal(member.kemPublicKey, shares[i],
                    CommitteeManager.shareAad(committee.id, member), 'shamir-share'),
                createdAt: new Date().toISOString()
            };
            fs.writeFileSync(path.join(dir, `${member.address}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
            member.hasShare = true;
        }

        committee.secretCommitment = crypto.createHash('sha256').update(secretHex).digest('hex');
        this.model.updateCommittee(committee);

        return { committeeId: committee.id, threshold, totalShares, sharesIssued: committee.members.length };
    }

    /** The sealed share record of one member (only that member can open it). */
    getMemberShareRecord(committeeId, memberAddress) {
        const file = path.join(this.sharesDir, committeeId, `${memberAddress}.json`);
        if (!fs.existsSync(file)) {
            throw new Error(`No share for ${memberAddress} in committee ${committeeId}`);
        }
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }

    /** Member side: open one's own share with one's ML-KEM secret key. */
    static async openMemberShare(record, kemSecretKey) {
        const aad = CommitteeManager.shareAad(record.committeeId,
            { address: record.memberAddress, shareIndex: record.shareIndex });
        return (await pqSeal.open(kemSecretKey, record.sealed, aad, 'shamir-share')).toString('utf8');
    }

    static shareAad(committeeId, member) {
        return `${committeeId}|${member.address}|${member.shareIndex}`;
    }

    /**
     * Reconstruct the committee secret from shares submitted by members.
     * @param {string} committeeId
     * @param {Array<{memberAddress: string, share: string}>} submittedShares
     */
    async getCommitteeSecret(committeeId, submittedShares) {
        const committee = this.model.getCommitteeById(committeeId);
        if (!committee) {
            throw new Error(`Committee ${committeeId} not found`);
        }
        if (!committee.secretCommitment) {
            throw new Error(`Committee ${committeeId} has no issued shares`);
        }
        const byMember = new Map();
        for (const s of submittedShares || []) {
            const member = committee.members.find(m => m.address === s.memberAddress);
            if (!member) throw new Error(`${s.memberAddress} is not a member of committee ${committeeId}`);
            byMember.set(member.address, s.share);
        }
        if (byMember.size < committee.threshold) {
            throw new Error(`Need shares from at least ${committee.threshold} distinct members, got ${byMember.size}`);
        }

        let secretHex;
        try {
            secretHex = secrets.combine([...byMember.values()]);
        } catch (e) {
            throw new Error(`Invalid share format: ${e.message}`);
        }
        const commitment = crypto.createHash('sha256').update(secretHex).digest('hex');
        if (commitment !== committee.secretCommitment) {
            throw new Error('Reconstructed secret does not match the committee commitment (invalid shares)');
        }
        return secretHex;
    }

    // Helper: Generate a random secret for a committee
    generateRandomSecret() {
        return crypto.randomBytes(32).toString('hex');
    }

    getAllCommittees() {
        return this.model.getAllCommittees();
    }

    getCommitteesByType(type) {
        return this.model.getCommitteesByType(type);
    }

    getCommittee(id) {
        return this.model.getCommitteeById(id);
    }

    getUserCommittees(userAddress) {
        return this.model.getCommitteesForUser(userAddress);
    }

    isUserInCommittee(committeeId, userAddress) {
        const committee = this.model.getCommitteeById(committeeId);
        if (!committee) return false;
        return committee.members.some(m => m.address === userAddress);
    }

    getCommitteeMembers(committeeId) {
        const committee = this.model.getCommitteeById(committeeId);
        return committee ? committee.members : [];
    }

    getThreshold(committeeId) {
        const committee = this.model.getCommitteeById(committeeId);
        return committee ? committee.threshold : null;
    }

    recordEvidenceTransfer(committeeId, evidenceId) {
        return this.model.addEvidenceToCommittee(committeeId, evidenceId);
    }
    // Get committee info for signcryption
    getCommitteeInfo(committeeId) {
        const committee = this.getCommittee(committeeId);
        if (!committee) return null;
        
        return {
            id: committee.id,
            name: committee.name,
            type: committee.type,
            threshold: committee.threshold,
            totalMembers: committee.totalMembers,
            members: committee.members.map(m => ({
                address: m.address,
                name: m.name,
                role: m.role,
                hasShare: m.hasShare
            }))
        };
    }

    // Check if committee is ready for signing
    isCommitteeReadyForSigning(committeeId) {
        const committee = this.getCommittee(committeeId);
        if (!committee) return false;
        
        const membersWithShares = committee.members.filter(m => m.hasShare);
        return membersWithShares.length >= committee.threshold;
    }

    // Get committee members with their addresses
    getCommitteeMembersForSigning(committeeId) {
        const committee = this.getCommittee(committeeId);
        if (!committee) return [];
        
        return committee.members.map(m => ({
            address: m.address,
            name: m.name,
            shareIndex: m.shareIndex
        }));
    }
}

module.exports = CommitteeManager;