// UI/utils/besuTransferClient.js
//
// Clean wrapper around the EvidenceReceiverV2 Solidity contract.
// Exposes prepare / commit / abort / status / getTransfer operations with
// per-call latency measurement and consistent error shapes.
//
// Reads the deployed contract address from UI/artifacts-v2/EvidenceReceiverV2.json,
// which is produced by deploy-v2-contract.js.

const fs   = require('fs');
const path = require('path');
const { Web3 } = require('web3');

// ─── Status enum, mirrors the Solidity contract ─────────────────────────
const STATUS = Object.freeze({
    NONE:      0,
    PREPARED:  1,
    COMMITTED: 2,
    ABORTED:   3
});
const STATUS_NAME = ['NONE', 'PREPARED', 'COMMITTED', 'ABORTED'];

class BesuTransferClient {
    /**
     * @param {Object} [opts]
     * @param {string} [opts.rpc]              - JSON-RPC URL (env BESU_RPC)
     * @param {string} [opts.coordinatorKey]   - hex private key (env COORDINATOR_KEY)
     * @param {string} [opts.contractAddress]  - V2 contract address (env V2_CONTRACT_ADDRESS)
     * @param {string} [opts.artifactPath]     - path to EvidenceReceiverV2.json
     */
    constructor(opts = {}) {
        const rpc = opts.rpc || process.env.BESU_RPC || 'http://localhost:8545';
        const coordinatorKey = opts.coordinatorKey || process.env.COORDINATOR_KEY;
        if (!coordinatorKey) {
            throw new Error('COORDINATOR_KEY env var (or opts.coordinatorKey) is required. See README.');
        }

        const artifactPath = opts.artifactPath ||
            path.resolve(__dirname, '../artifacts-v2/EvidenceReceiverV2.json');

        let artifact = null;
        if (fs.existsSync(artifactPath)) {
            artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
        }

        const contractAddress = opts.contractAddress ||
            process.env.V2_CONTRACT_ADDRESS ||
            (artifact && artifact.address);

        if (!contractAddress) {
            throw new Error(
                'BesuTransferClient: contract address not found. ' +
                `Pass contractAddress, set V2_CONTRACT_ADDRESS env var, or run deploy-v2-contract.js to create ${artifactPath}`
            );
        }
        if (!artifact || !artifact.abi) {
            throw new Error(
                `BesuTransferClient: ABI not found at ${artifactPath}. ` +
                'Run deploy-v2-contract.js first.'
            );
        }

        this.web3 = new Web3(rpc);
        this.account = this.web3.eth.accounts.privateKeyToAccount(coordinatorKey);
        this.web3.eth.accounts.wallet.add(this.account);
        this.from = this.account.address;

        this.contract = new this.web3.eth.Contract(artifact.abi, contractAddress);
        this.contractAddress = contractAddress;

        this.defaultGas = Number(opts.defaultGas) || 500_000;
    }

    /**
     * txId must be a 32-byte hex string with 0x prefix ("0x" + 64 hex chars).
     * This helper normalises "bare" hex or ASCII txIds into the Solidity form.
     */
    static normalizeTxId(txId) {
        if (typeof txId !== 'string') {
            throw new Error('BesuTransferClient.normalizeTxId: txId must be a string');
        }
        let hex = txId.startsWith('0x') ? txId.slice(2) : txId;
        // If it's valid hex and 64 chars, use as-is.
        if (/^[0-9a-fA-F]{64}$/.test(hex)) return '0x' + hex.toLowerCase();
        // Otherwise hash the input via web3.utils.keccak256 to get a deterministic 32-byte id.
        return require('web3').Web3.utils.keccak256(txId);
    }

    // ─── Writes ──────────────────────────────────────────────────────────

    async prepare({ txId, evidenceId, metadataHash, algorithm, bundleHash }) {
        const t0 = Date.now();
        const normalizedTxId = BesuTransferClient.normalizeTxId(txId);
        const metaHashBytes32 = this._toBytes32(metadataHash, 'metadataHash');
        const bundleHashBytes32 = this._toBytes32(bundleHash, 'bundleHash');

        const receipt = await this.contract.methods.prepare(
            normalizedTxId, evidenceId, metaHashBytes32, algorithm, bundleHashBytes32
        ).send({ from: this.from, gas: this.defaultGas });

        return {
            success: true,
            txId: normalizedTxId,
            txHash: receipt.transactionHash,
            blockNumber: Number(receipt.blockNumber),
            latencyMs: Date.now() - t0
        };
    }

    async commit(txId) {
        const t0 = Date.now();
        const normalizedTxId = BesuTransferClient.normalizeTxId(txId);
        const receipt = await this.contract.methods.commit(normalizedTxId)
            .send({ from: this.from, gas: 200_000 });
        return {
            success: true,
            txId: normalizedTxId,
            txHash: receipt.transactionHash,
            blockNumber: Number(receipt.blockNumber),
            latencyMs: Date.now() - t0
        };
    }

    async abort(txId, reason = '') {
        const t0 = Date.now();
        const normalizedTxId = BesuTransferClient.normalizeTxId(txId);
        const receipt = await this.contract.methods.abortTransfer(normalizedTxId, reason)
            .send({ from: this.from, gas: 200_000 });
        return {
            success: true,
            txId: normalizedTxId,
            txHash: receipt.transactionHash,
            blockNumber: Number(receipt.blockNumber),
            latencyMs: Date.now() - t0
        };
    }

    // ─── Reads ───────────────────────────────────────────────────────────

    async getStatus(txId) {
        const normalizedTxId = BesuTransferClient.normalizeTxId(txId);
        const raw = await this.contract.methods.getStatus(normalizedTxId).call();
        const status = Number(raw);
        return { status, statusName: STATUS_NAME[status] };
    }

    async getTransfer(txId) {
        const normalizedTxId = BesuTransferClient.normalizeTxId(txId);
        const r = await this.contract.methods.getTransfer(normalizedTxId).call();
        return {
            evidenceId:   r.evidenceId,
            metadataHash: r.metadataHash,
            bundleHash:   r.bundleHash,
            algorithm:    r.algorithm,
            status:       Number(r.status),
            statusName:   STATUS_NAME[Number(r.status)],
            preparedAt:   Number(r.preparedAt),
            committedAt:  Number(r.committedAt),
            abortedAt:    Number(r.abortedAt),
            abortReason:  r.abortReason
        };
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    _toBytes32(value, field) {
        if (typeof value !== 'string') throw new Error(`${field} must be a string`);
        let hex = value.startsWith('0x') ? value.slice(2) : value;
        if (/^[0-9a-fA-F]{64}$/.test(hex)) return '0x' + hex.toLowerCase();
        // Hash shorter values so callers can pass the "32-byte hash" from the paper.
        return this.web3.utils.keccak256(value);
    }
}

BesuTransferClient.STATUS      = STATUS;
BesuTransferClient.STATUS_NAME = STATUS_NAME;

module.exports = BesuTransferClient;
