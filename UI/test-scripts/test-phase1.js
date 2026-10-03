// UI/test-scripts/test-phase1.js
const CommitteeManager = require('../utils/committeeManager');
const { ClientApplication } = require('../../Client/client');

async function testPhase1() {
    console.log('🧪 Testing Phase 1: Committee Management\n');
    
    try {
        console.log('Initializing CommitteeManager...');
        const committeeManager = new CommitteeManager();
        
        console.log('Initializing ClientApplication...');
        const clientApp = new ClientApplication();
        
        // 1. Get existing users
        console.log('\n1. Fetching registered users from blockchain...');
        const users = await clientApp.getAllUsers();
        console.log(`   ✅ Found ${users.length} users`);
        
        if (users.length === 0) {
            console.log('   ⚠️ No users found!');
            console.log('   Please register users at: http://localhost:3000/register');
            return;
        }
        
        // Display users found
        console.log('\n   Registered users:');
        users.slice(0, 5).forEach((u, i) => {
            console.log(`   ${i+1}. ${u.name} (${u.userId?.substring(0, 20)}...)`);
        });
        
        if (users.length < 3) {
            console.log('\n   ⚠️ Need at least 3 users. Please register more users first.');
            console.log('   Visit http://localhost:3000/register to create more users');
            return;
        }
        
        // 2. Create a test committee
        console.log('\n2. Creating test committee...');
        const committeeData = {
            name: 'Test Police Committee',
            type: 'police',
            description: 'Test committee for threshold signcryption',
            threshold: 3,
            members: users.slice(0, 5).map((u, i) => ({
                address: u.userId,
                name: u.name,
                role: i === 0 ? 'Chair' : (i === 1 ? 'Secretary' : 'Member')
            }))
        };
        
        const testUser = { address: users[0].userId };
        const committee = await committeeManager.createCommittee(committeeData, testUser);
        console.log(`   ✅ Committee created:`);
        console.log(`      Name: ${committee.name}`);
        console.log(`      ID: ${committee.id}`);
        console.log(`      Threshold: ${committee.threshold}/${committee.totalMembers}`);
        console.log(`      Members: ${committee.members.map(m => m.name).join(', ')}`);
        
        // 3. Get all committees
        console.log('\n3. Fetching all committees...');
        const allCommittees = committeeManager.getAllCommittees();
        console.log(`   ✅ Total committees: ${allCommittees.length}`);
        
        // 4. Get user's committees
        console.log('\n4. Fetching user committees...');
        const userCommittees = committeeManager.getUserCommittees(testUser.address);
        console.log(`   ✅ User is in ${userCommittees.length} committees`);
        
        if (userCommittees.length > 0) {
            console.log('\n   User committees:');
            userCommittees.forEach(c => {
                console.log(`   - ${c.name} (${c.type}, t=${c.threshold}/${c.totalMembers})`);
            });
        }
        
        console.log('\n✅✅✅ Phase 1 tests passed! ✅✅✅');
        console.log('\n🌐 You can now access committees at: http://localhost:3000/committees');
        console.log('📁 Committee data stored in: UI/data/committees.json');
        
    } catch (error) {
        console.error('\n❌ ERROR in testPhase1:', error.message);
        console.error('Stack trace:', error.stack);
    }
}

// Run the test with proper error handling
console.log('Starting test...');
testPhase1().catch(err => {
    console.error('Unhandled error:', err);
});