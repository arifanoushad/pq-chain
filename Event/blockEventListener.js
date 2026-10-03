const { EventListener } = require('./event');

async function main() {
    const listener = new EventListener();
    await listener.blockEventListener('PoliceOrg', 'Admin', 'evidencechannel');
}

main().catch((error) => {
    console.error('❌ Error running block event listener:', error);
});

