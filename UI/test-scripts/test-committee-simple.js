// test-committee-simple.js - No blockchain dependency
const CommitteeManager = require('../utils/committeeManager');
const UserManager = require('../utils/userManager');

async function testCommittee() {
    console.log('🧪 Testing Committee Management (Local Only)\n');
    
    try {
        const committeeManager = new CommitteeManager();
        const userManager = new UserManager();
        
        console.log('1. Fetching local users...');
        const users = userManager.getUsers();
        console.log(`   Found ${users.length} users locally`);
        
        if (users.length < 3) {
            console.log('   Need at least 3 users. Register more users first.');
            return;
        }
        
        users.slice(0, 5).forEach((u, i) => {
            console.log(`   ${i+1}. ${u.name} (${u.algorithm})`);
        });
        
        console.log('\n2. Creating test committee...');
        const committeeData = {
            name: 'Test Research Committee',
            type: 'police',
            description: 'Committee for PQC research testing',
            threshold: 3,
            members: users.slice(0, 5).map((u, i) => ({
                address: u.address,
                name: u.name,
                role: i === 0 ? 'Chair' : (i === 1 ? 'Secretary' : 'Member')
            }))
        };
        
        const testUser = { address: users[0].address };
        const committee = await committeeManager.createCommittee(committeeData, testUser);
        
        console.log(`   Committee created: ${committee.name}`);
        console.log(`   ID: ${committee.id}`);
        console.log(`   Threshold: ${committee.threshold}/${committee.totalMembers}`);
        
        console.log('\n✅ Test passed!');
        
    } catch (error) {
        console.error('\n❌ Error:', error.message);
        console.error(error.stack);
    }
}

testCommittee();
