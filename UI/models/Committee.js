// UI/models/Committee.js
const fs = require('fs');
const path = require('path');

class CommitteeModel {
    constructor(dataPath) {
        // Use existing data folder (overridable, e.g. for tests)
        this.dataPath = dataPath || path.join(__dirname, '../data/committees.json');
        this.ensureDataFile();
    }

    ensureDataFile() {
        if (!fs.existsSync(this.dataPath)) {
            fs.writeFileSync(this.dataPath, JSON.stringify([], null, 2));
        }
    }

    createCommittee(committeeData) {
        const committees = this.getAllCommittees();
        
        const newCommittee = {
            id: `cmt_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`,
            name: committeeData.name,
            type: committeeData.type,
            description: committeeData.description || '',
            threshold: committeeData.threshold,
            totalMembers: committeeData.members.length,
            members: committeeData.members.map((m, idx) => ({
                id: `member_${idx + 1}`,
                address: m.address,
                name: m.name,
                role: m.role,
                shareIndex: idx + 1,
                kemPublicKey: m.kemPublicKey || null,   // ML-KEM-768 key the member's share is sealed to
                hasShare: false,
                joinedAt: new Date().toISOString()
            })),
            status: 'active',
            createdAt: new Date().toISOString(),
            createdBy: committeeData.createdBy,
            evidenceIds: []
        };

        committees.push(newCommittee);
        this.saveCommittees(committees);
        return newCommittee;
    }

    getAllCommittees() {
        const data = fs.readFileSync(this.dataPath, 'utf8');
        return JSON.parse(data);
    }

    getCommitteeById(id) {
        const committees = this.getAllCommittees();
        return committees.find(c => c.id === id);
    }

    getCommitteesByType(type) {
        const committees = this.getAllCommittees();
        return committees.filter(c => c.type === type);
    }

    getCommitteesForUser(userAddress) {
        const committees = this.getAllCommittees();
        return committees.filter(c => 
            c.members.some(m => m.address === userAddress) && c.status === 'active'
        );
    }

    addEvidenceToCommittee(committeeId, evidenceId) {
        const committees = this.getAllCommittees();
        const committee = committees.find(c => c.id === committeeId);
        
        if (committee && !committee.evidenceIds.includes(evidenceId)) {
            committee.evidenceIds.push(evidenceId);
            this.saveCommittees(committees);
            return true;
        }
        return false;
    }

    updateCommittee(updated) {
        const committees = this.getAllCommittees();
        const i = committees.findIndex(c => c.id === updated.id);
        if (i < 0) throw new Error(`Committee ${updated.id} not found`);
        committees[i] = updated;
        this.saveCommittees(committees);
    }

    saveCommittees(committees) {
        fs.writeFileSync(this.dataPath, JSON.stringify(committees, null, 2));
    }
}

module.exports = CommitteeModel;