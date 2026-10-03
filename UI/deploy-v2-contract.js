// UI/deploy-v2-contract.js
//
// Compiles and deploys EvidenceReceiverV2.sol to a running Besu node.
//
// ─── v2: EVM version pin ────────────────────────────────────────────────
// solc ≥ 0.8.20 defaults to emitting the PUSH0 opcode (EIP-3855, Shanghai).
// Besu's `--network=dev` profile runs an older EVM spec that does not
// recognise PUSH0, causing "Transaction processing could not be completed
// due to an exception: INVALID_OPERATION" on contract creation.
//
// We therefore compile with `evmVersion: "london"` — the pre-Shanghai
// target that every modern Besu accepts.  If you're on a Shanghai-enabled
// genesis, you can override with EVM_VERSION=paris or =shanghai in the env.
//
// Run from UI/ directory:
//
//   node deploy-v2-contract.js
//
// Environment variables:
//   BESU_RPC            - JSON-RPC URL               (default: http://localhost:8545)
//   COORDINATOR_KEY     - deployer private key (hex), required; for a Besu
//                         --network=dev node see README ("Besu key")
//   V2_SOL_PATH         - path to EvidenceReceiverV2.sol
//                         (default: ./EvidenceReceiverV2.sol)
//   EVM_VERSION         - solc evmVersion target     (default: london)

const fs   = require('fs');
const path = require('path');
const solc = require('solc');
const { Web3 } = require('web3');

const BESU_RPC    = process.env.BESU_RPC    || 'http://localhost:8545';
// Default to the well-known Besu `--network=dev` prefunded miner key,
// which matches --miner-coinbase=0xfe3b557e8fb62b89f4916b721be55ceb828dbd73
const COORDINATOR_KEY = process.env.COORDINATOR_KEY;
if (!COORDINATOR_KEY) {
    console.error('❌ COORDINATOR_KEY env var is required (deployer private key, hex). See README.');
    process.exit(1);
}
const V2_SOL_PATH = process.env.V2_SOL_PATH || './EvidenceReceiverV2.sol';
const EVM_VERSION = process.env.EVM_VERSION || 'london';

function compile(solPath, evmVersion) {
    const source = fs.readFileSync(solPath, 'utf8');
    const fileName = path.basename(solPath);

    const input = {
        language: 'Solidity',
        sources: { [fileName]: { content: source } },
        settings: {
            optimizer: { enabled: true, runs: 200 },
            evmVersion: evmVersion,      // ← pin to avoid PUSH0 on dev Besu
            outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } }
        }
    };

    console.log(`🔨 Compiling ${fileName} with solc ${solc.version()} (evmVersion=${evmVersion})`);
    const output = JSON.parse(solc.compile(JSON.stringify(input)));

    if (output.errors) {
        const fatal = output.errors.filter(e => e.severity === 'error');
        if (fatal.length) {
            for (const e of fatal) console.error(e.formattedMessage);
            throw new Error('Solidity compilation failed');
        }
        for (const e of output.errors) console.warn(e.formattedMessage);
    }

    const contractName = 'EvidenceReceiverV2';
    const artifact = output.contracts[fileName][contractName];
    if (!artifact) {
        throw new Error(`Contract ${contractName} not found in compilation output`);
    }

    return {
        abi:      artifact.abi,
        bytecode: '0x' + artifact.evm.bytecode.object,
        evmVersion: evmVersion
    };
}

async function ensureFunded(web3, address) {
    const balance = await web3.eth.getBalance(address);
    const balanceEth = web3.utils.fromWei(balance, 'ether');
    console.log(`💰 Deployer balance: ${balanceEth} ETH`);
    if (balance === 0n || balance === '0' || balance === 0) {
        throw new Error(
            `Deployer ${address} has zero balance on this Besu instance. ` +
            `Either (a) set COORDINATOR_KEY to a prefunded address's private key, ` +
            `or (b) fund ${address} from the miner account.`
        );
    }
}

async function deploy() {
    const web3 = new Web3(BESU_RPC);

    const account = web3.eth.accounts.privateKeyToAccount(COORDINATOR_KEY);
    web3.eth.accounts.wallet.add(account);
    console.log(`🔑 Deployer / initial coordinator: ${account.address}`);

    const chainId = await web3.eth.getChainId();
    console.log(`⛓️  Connected to Besu chainId=${chainId}`);

    await ensureFunded(web3, account.address);

    const artifact = compile(V2_SOL_PATH, EVM_VERSION);

    console.log('🚀 Deploying EvidenceReceiverV2…');
    const contract = new web3.eth.Contract(artifact.abi);
    const tx = contract.deploy({ data: artifact.bytecode });

    let gas;
    try {
        gas = await tx.estimateGas({ from: account.address });
        console.log(`   Estimated gas: ${gas}`);
    } catch (e) {
        console.warn(`   gas estimation failed (${e.message}); using fallback 3,000,000`);
        gas = 3_000_000n;
    }

    const deployed = await tx.send({
        from: account.address,
        gas:  Number(gas) + 50_000
    });

    console.log('\n✅ Deployment successful');
    console.log(`   Contract address: ${deployed.options.address}`);
    console.log(`   Coordinator:      ${account.address}`);
    console.log(`   EVM target:       ${artifact.evmVersion}`);

    const artifactsDir = path.resolve(__dirname, './artifacts-v2');
    if (!fs.existsSync(artifactsDir)) fs.mkdirSync(artifactsDir);
    fs.writeFileSync(
        path.join(artifactsDir, 'EvidenceReceiverV2.json'),
        JSON.stringify({
            address:     deployed.options.address,
            coordinator: account.address,
            abi:         artifact.abi,
            evmVersion:  artifact.evmVersion,
            deployedAt:  new Date().toISOString(),
            chainId:     chainId.toString()
        }, null, 2)
    );
    console.log(`   Artifact saved:   ${path.join(artifactsDir, 'EvidenceReceiverV2.json')}`);

    console.log(`\nExport this for the test script:`);
    console.log(`   export V2_CONTRACT_ADDRESS=${deployed.options.address}`);
}

deploy().catch(err => {
    console.error('❌ Deployment failed:', err.message);
    process.exit(1);
});
