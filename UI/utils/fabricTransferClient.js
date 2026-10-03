// UI/utils/fabricTransferClient.js
//
// Dual-mode client for the Fabric-side 2PC transfer methods.
//
// ─── Modes ──────────────────────────────────────────────────────────────
// Mode A ("real"):
//     Fabric chaincode has been redeployed with evidence-transfer.go.
//     This client calls PrepareTransfer / CommitTransfer / AbortTransfer /
//     GetTransferStatus via the Hyperledger Fabric Node SDK.
//
// Mode B ("stub", test fixture only):
//     Fabric chaincode has NOT been redeployed yet.
//     This client accepts the same calls, logs them, persists a JSON
//     journal to UI/data/fabric-stub-journal.jsonl, and returns success.
//     This lets the 2PC coordinator exercise the full happy / abort /
//     rollback logic end-to-end using Besu as the "real" chain while
//     Fabric participation is audited but deferred.
//
// Mode is chosen by environment:
//     FABRIC_MODE=real  ⇒ use the Fabric SDK (requires connection profile)
//     FABRIC_MODE=stub  ⇒ journal-only test fixture (never the default)
//     FABRIC_MODE=off   ⇒ skip Fabric entirely; coordinator runs Besu-only
//
// When you later switch to real mode, no changes to the coordinator or
// benchmarks are required — only the env var flip.

const fs   = require('fs');
const path = require('path');

const VALID  = new Set(['real', 'stub', 'off']);

const DEFAULT_JOURNAL = path.resolve(__dirname, '../data/fabric-stub-journal.jsonl');

class FabricTransferClient {
    constructor(opts = {}) {
        // No silent default: the stub is a labelled test fixture, and the
        // mode must be chosen explicitly (opts.mode or FABRIC_MODE).
        this.mode = (opts.mode || process.env.FABRIC_MODE || '').toLowerCase();
        if (!VALID.has(this.mode)) {
            throw new Error(`FabricTransferClient: set FABRIC_MODE (or opts.mode) to real|stub|off; got "${this.mode}"`);
        }
        this.journalPath = opts.journalPath || DEFAULT_JOURNAL;

        if (this.mode === 'stub') {
            const dir = path.dirname(this.journalPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            if (!fs.existsSync(this.journalPath)) fs.writeFileSync(this.journalPath, '');
            console.log(`ℹ️  FabricTransferClient running in STUB mode; journal=${this.journalPath}`);
        } else if (this.mode === 'off') {
            console.log('ℹ️  FabricTransferClient running in OFF mode; Fabric calls are no-ops');
        } else if (this.mode === 'real') {
            // Lazy-load the Fabric SDK only in real mode so dev machines
            // without the SDK installed can still run stub/off.
            try {
                this.gateway = require('fabric-network').Gateway;
                this.wallets = require('fabric-network').Wallets;
            } catch (e) {
                throw new Error(
                    'FABRIC_MODE=real but fabric-network is not installed. ' +
                    'Install with: npm install fabric-network'
                );
            }
            // Defaults match the Minifab network (Network/startNetwork.sh);
            // override with opts or FABRIC_CCP / FABRIC_WALLET / FABRIC_CHANNEL /
            // FABRIC_IDENTITY / FABRIC_CHAINCODE.
            const profiles = path.resolve(__dirname, '../../Network/vars/profiles');
            const ccpPath = process.env.FABRIC_CCP ||
                path.join(profiles, 'evidencechannel_connection_for_nodesdk.json');
            this.connectionProfile = opts.connectionProfile ||
                (fs.existsSync(ccpPath) ? JSON.parse(fs.readFileSync(ccpPath, 'utf8')) : null);
            this.walletPath    = opts.walletPath || process.env.FABRIC_WALLET ||
                path.join(profiles, 'vscode/wallets/PoliceOrg.evidence.com');
            this.channelName   = opts.channelName   || process.env.FABRIC_CHANNEL   || 'evidencechannel';
            this.chaincodeName = opts.chaincodeName || process.env.FABRIC_CHAINCODE || 'evidence';
            this.identityLabel = opts.identityLabel || process.env.FABRIC_IDENTITY  || 'Admin';
            if (!this.connectionProfile || !fs.existsSync(this.walletPath)) {
                throw new Error(
                    `FABRIC_MODE=real: connection profile (${ccpPath}) or wallet (${this.walletPath}) not found`
                );
            }
            console.log('ℹ️  FabricTransferClient running in REAL mode');
        }
    }

    // ─── Public API (same shape regardless of mode) ─────────────────────

    async prepare({ txId, evidenceId, metadataHash, signerSet, bundleHash, algorithm, targetChain = 'besu' }) {
        return this._invoke('PrepareTransfer', {
            txId, evidenceId, metadataHash, signerSet, bundleHash, algorithm, targetChain
        }, [
            txId, evidenceId, metadataHash,
            JSON.stringify(signerSet), bundleHash, algorithm, targetChain
        ]);
    }

    async commit(txId) {
        return this._invoke('CommitTransfer', { txId }, [txId]);
    }

    async abort(txId, reason = '') {
        return this._invoke('AbortTransfer', { txId, reason }, [txId, reason]);
    }

    async getStatus(txId) {
        return this._query('GetTransferStatus', { txId }, [txId]);
    }

    /** Full CrossChainTransfer record (bundleHash, signerSet, ...); used by auditors. */
    async getTransfer(txId) {
        return this._query('GetTransfer', { txId }, [txId]);
    }

    // ─── Dispatch ───────────────────────────────────────────────────────

    async _invoke(fn, params, args) {
        const t0 = Date.now();
        if (this.mode === 'off') {
            return { success: true, mode: 'off', fn, latencyMs: 0 };
        }
        if (this.mode === 'stub') {
            this._journal({ type: 'invoke', fn, params, ts: new Date().toISOString() });
            // Simulate deterministic success so the coordinator can proceed.
            return {
                success: true,
                mode: 'stub',
                fn,
                simulated: this._simulatedResultFor(fn),
                latencyMs: Date.now() - t0
            };
        }
        // real
        return this._realInvoke(fn, args, t0);
    }

    async _query(fn, params, args) {
        const t0 = Date.now();
        if (this.mode === 'off') {
            return { success: true, mode: 'off', fn, result: 'NONE', latencyMs: 0 };
        }
        if (this.mode === 'stub') {
            this._journal({ type: 'query', fn, params, ts: new Date().toISOString() });
            // The stub replays its journaled writes for this txId.
            const simulated = fn === 'GetTransfer'
                ? this._stubTransferFor(params.txId)
                : this._stubStatusFor(params.txId);
            return {
                success: true,
                mode: 'stub',
                fn,
                result: simulated,
                latencyMs: Date.now() - t0
            };
        }
        return this._realQuery(fn, args, t0);
    }

    // ─── Stub helpers ───────────────────────────────────────────────────

    _journal(entry) {
        fs.appendFileSync(this.journalPath, JSON.stringify(entry) + '\n');
    }

    _simulatedResultFor(fn) {
        // Matches the Go chaincode's return semantics.
        if (fn === 'PrepareTransfer') return 'PREPARED';
        if (fn === 'CommitTransfer')  return 'COMMITTED';
        if (fn === 'AbortTransfer')   return 'ABORTED';
        return 'OK';
    }

    _stubStatusFor(txId) {
        // Reconstruct the current per-txId state from the journal.
        if (!fs.existsSync(this.journalPath)) return 'NONE';
        const lines = fs.readFileSync(this.journalPath, 'utf8').split('\n').filter(Boolean);
        let state = 'NONE';
        for (const line of lines) {
            let entry;
            try { entry = JSON.parse(line); } catch { continue; }
            if (entry.type !== 'invoke') continue;
            if (entry.params.txId !== txId) continue;
            if (entry.fn === 'PrepareTransfer') state = 'PREPARED';
            else if (entry.fn === 'CommitTransfer') state = 'COMMITTED';
            else if (entry.fn === 'AbortTransfer') state = 'ABORTED';
        }
        return state;
    }

    _stubTransferFor(txId) {
        // Rebuild the CrossChainTransfer record the chaincode would hold.
        if (!fs.existsSync(this.journalPath)) return null;
        const lines = fs.readFileSync(this.journalPath, 'utf8').split('\n').filter(Boolean);
        let record = null;
        for (const line of lines) {
            let entry;
            try { entry = JSON.parse(line); } catch { continue; }
            if (entry.type !== 'invoke' || entry.params.txId !== txId) continue;
            if (entry.fn === 'PrepareTransfer' && !record) {
                const { evidenceId, metadataHash, signerSet, bundleHash, algorithm, targetChain } = entry.params;
                record = { txId, evidenceId, metadataHash, signerSet, bundleHash, algorithm, targetChain, status: 'PREPARED' };
            } else if (record && entry.fn === 'CommitTransfer') record.status = 'COMMITTED';
            else if (record && entry.fn === 'AbortTransfer')    record.status = 'ABORTED';
        }
        return record;
    }

    // ─── Real-mode plumbing (used once chaincode is redeployed) ─────────

    async _realInvoke(fn, args, t0) {
        const { contract } = await this._connect();
        try {
            const result = await contract.submitTransaction(fn, ...args);
            return {
                success: true, mode: 'real', fn,
                result: result.toString(),
                latencyMs: Date.now() - t0
            };
        } catch (e) {
            throw new Error(`Fabric ${fn} failed: ${e.message}`);
        }
    }

    async _realQuery(fn, args, t0) {
        const { contract } = await this._connect();
        try {
            const result = await contract.evaluateTransaction(fn, ...args);
            return {
                success: true, mode: 'real', fn,
                result: fn === 'GetTransfer' ? JSON.parse(result.toString()) : result.toString(),
                latencyMs: Date.now() - t0
            };
        } catch (e) {
            throw new Error(`Fabric ${fn} query failed: ${e.message}`);
        }
    }

    // One gateway connection is kept for the client's lifetime (as a
    // long-running coordinator would); call close() when done.
    async _connect() {
        if (!this._connection) {
            this._connection = (async () => {
                const wallet = await this.wallets.newFileSystemWallet(this.walletPath);
                const gateway = new this.gateway();
                await gateway.connect(this.connectionProfile, {
                    wallet,
                    identity: this.identityLabel,
                    discovery: { enabled: true, asLocalhost: true }
                });
                const network = await gateway.getNetwork(this.channelName);
                const contract = network.getContract(this.chaincodeName);
                return { gateway, network, contract };
            })().catch(e => { this._connection = null; throw e; });
        }
        return this._connection;
    }

    async close() {
        if (this._connection) {
            const { gateway } = await this._connection.catch(() => ({}));
            this._connection = null;
            if (gateway) gateway.disconnect();
        }
    }
}

FabricTransferClient.MODES = ['real', 'stub', 'off'];

module.exports = FabricTransferClient;
