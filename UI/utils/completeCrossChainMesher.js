// UI/utils/completeCrossChainMesher.js
//
// Real two-phase-commit (2PC) coordinator for cross-chain forensic
// evidence transfer.  Drives Fabric (source) and Besu (target) through
// prepare → commit (success path) or prepare → abort (failure path).
//
// ─── Design ─────────────────────────────────────────────────────────────
//
// Phase 0 — Store bundle (JISA R1.4):
//   - Coordinator encodes the multi-signature bundle canonically and
//     stores it durably (IPFS pin(s) + local archive, see bundleStore.js)
//   - bundleHash = SHA-256(canonical bytes) is the only bundle data
//     written on-chain; if storing fails, no chain is touched
//
// Phase 1 — Prepare:
//   - Coordinator computes txId = SHA-256(evidenceId | timestamp | metadataHash)
//   - Writes a TXN_STARTED entry to the persistent coordinator log
//   - Calls Fabric.prepare(...) and Besu.prepare(...) IN PARALLEL with a
//     configurable timeout (default 30 s) on each
//   - If BOTH succeed → transition to commit phase
//   - If EITHER fails or times out → transition to abort phase
//
// Phase 2 — Commit (success path):
//   - Calls Fabric.commit(txId) and Besu.commit(txId) in parallel
//   - Both calls are idempotent on the on-chain side, so retry is safe
//   - On any retryable failure, retry up to MAX_RETRIES; on hard failure,
//     log a CRITICAL entry (operator must reconcile manually)
//   - On success → write TXN_COMMITTED to the log, return success
//
// Phase 2 — Abort (failure path):
//   - Calls Fabric.abort(txId, reason) and Besu.abort(txId, reason)
//   - If the counterpart chain never prepared, abort is a no-op
//   - A prepare that timed out may still land: wait up to abortGraceMs and
//     abort it if it does; if still unresolved, log ABORT_PENDING (not
//     terminal) so that recoverPendingTransfers() aborts it later
//   - On success → write TXN_ABORTED to the log, return rolled-back
//
// ─── Crash recovery ─────────────────────────────────────────────────────
// The coordinator log is append-only JSONL at UI/data/mesher-log.jsonl.
// On startup, `recoverPendingTransfers()` replays the log, identifies any
// transfers that started but have no terminal entry (COMMITTED / ABORTED /
// ABORT_FAILED), queries both chains for current status, and resolves:
//   - Both chains PREPARED  → issue commits (default) or aborts (opt-in)
//   - One chain PREPARED, other NONE → abort the prepared side
//   - Both chains terminal → write the missing log entry and close
//
// This is the standard 2PC coordinator recovery pattern: on-chain state
// is authoritative, the log is hint-only.
//
// ─── Honest framing for the paper ───────────────────────────────────────
// - Fabric participation depends on FABRIC_MODE (real | stub | off).
//   In stub/off modes, the coordinator still drives a real 2PC protocol
//   against Besu; the Fabric side is journaled but not cryptographically
//   committed until you redeploy the chaincode with evidence-transfer.go.
// - Until Fabric is in "real" mode, Theorem 5 (chain-of-custody) holds
//   only for the Besu side. This is disclosed in the benchmark output
//   and should be disclosed in the paper's evaluation section.

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const BesuTransferClient      = require('./besuTransferClient');
const FabricTransferClient    = require('./fabricTransferClient');
const BundleStore             = require('./bundleStore');
const ThresholdMultiSignature = require('./thresholdMultiSignature');

const LOG_PATH = path.resolve(__dirname, '../data/mesher-log.jsonl');

const DEFAULTS = {
    storeTimeoutMs:   60_000,
    prepareTimeoutMs: 30_000,
    abortGraceMs:     null,      // wait for a timed-out prepare to settle; default = prepareTimeoutMs
    maxRetries:       3,
    retryBackoffMs:   1_000
};

// ─── Log entry types ────────────────────────────────────────────────────
const ENTRY = Object.freeze({
    BUNDLE_STORED:     'BUNDLE_STORED',
    TXN_STARTED:       'TXN_STARTED',
    PREPARE_OK:        'PREPARE_OK',
    PREPARE_FAILED:    'PREPARE_FAILED',
    COMMIT_OK:         'COMMIT_OK',
    COMMIT_FAILED:     'COMMIT_FAILED',
    ABORT_OK:          'ABORT_OK',
    ABORT_FAILED:      'ABORT_FAILED',
    TXN_COMMITTED:     'TXN_COMMITTED',
    TXN_ABORTED:       'TXN_ABORTED',
    ABORT_PENDING:     'ABORT_PENDING',
    TXN_RECOVERED:     'TXN_RECOVERED',
    CRITICAL:          'CRITICAL'
});

class CompleteCrossChainMesher {
    constructor(opts = {}) {
        this.besu   = opts.besu   || new BesuTransferClient(opts.besuOpts);
        this.fabric = opts.fabric || new FabricTransferClient(opts.fabricOpts);
        this.bundleStore = opts.bundleStore || new BundleStore(opts.bundleStoreOpts);
        this.config = { ...DEFAULTS, ...opts.config };
        this.logPath = opts.logPath || LOG_PATH;

        const dir = path.dirname(this.logPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        if (!fs.existsSync(this.logPath)) fs.writeFileSync(this.logPath, '');
    }

    // ─── Public API ──────────────────────────────────────────────────────

    /**
     * Generate a deterministic txId from evidence metadata.
     * Making this deterministic allows retries to reuse the same txId.
     */
    computeTxId({ evidenceId, metadataHash, timestamp }) {
        const ts = timestamp ?? Date.now();
        const input = `${evidenceId}|${ts}|${metadataHash}`;
        return '0x' + crypto.createHash('sha256').update(input).digest('hex');
    }

    /**
     * Drive a full 2PC for one evidence transfer.
     *
     * @param {Object}   params
     * @param {string}   params.evidenceId
     * @param {string}   params.metadataHash    - hex SHA-256 (32 B) of metadata
     * @param {Object}   params.multiSigBundle  - from ThresholdMultiSignature.combinePartialSignatures
     * @param {string}   params.algorithm
     * @param {string[]} params.signerSet       - must equal the bundle's signer addresses
     * @returns {Promise<Object>} aggregate result
     */
    async transfer({
        evidenceId,
        metadataHash,
        multiSigBundle,
        algorithm,
        signerSet
    }) {
        if (!evidenceId || !metadataHash) {
            throw new Error('mesher.transfer: evidenceId and metadataHash are required');
        }
        if (!multiSigBundle) {
            throw new Error('mesher.transfer: multiSigBundle is required (it is stored before prepare)');
        }
        if (!algorithm || !Array.isArray(signerSet) || signerSet.length === 0) {
            throw new Error('mesher.transfer: algorithm and non-empty signerSet are required');
        }
        if (multiSigBundle.algorithm !== algorithm || multiSigBundle.evidenceHash !== metadataHash) {
            throw new Error('mesher.transfer: bundle algorithm / evidenceHash do not match the request');
        }
        // Fabric records signerSet on-chain as the durable record of who
        // signed, so it must be exactly the bundle's signers.
        const bundleSigners = multiSigBundle.partials.map(p => p.memberAddress);
        if (bundleSigners.length !== signerSet.length ||
            bundleSigners.some((a, i) => a !== signerSet[i])) {
            throw new Error('mesher.transfer: signerSet does not match the bundle signers');
        }

        const bundleBytes = ThresholdMultiSignature.encodeBundle(multiSigBundle);

        const timestamp = Date.now();
        const txId = this.computeTxId({ evidenceId, metadataHash, timestamp });

        const t0 = Date.now();
        const phaseTimings = { total: 0, store: 0, prepare: 0, finalize: 0 };

        // ─── Phase 0: Store the bundle durably before any chain is touched ─
        let stored;
        try {
            stored = await this._withTimeout(
                this.bundleStore.put(bundleBytes),
                this.config.storeTimeoutMs, 'bundleStore.put'
            );
        } catch (e) {
            phaseTimings.store = Date.now() - t0;
            phaseTimings.total = phaseTimings.store;
            const reason = `bundle-store-failure: ${e.message}`;
            this._log({ type: ENTRY.TXN_ABORTED, txId, evidenceId, reason, phaseTimings });
            return { success: false, outcome: 'ABORTED', txId, reason, phaseTimings, details: { store: { error: e.message } } };
        }
        phaseTimings.store = Date.now() - t0;
        const resolvedBundleHash = stored.bundleHash;

        this._log({
            type: ENTRY.BUNDLE_STORED,
            txId, bundleHash: resolvedBundleHash, cid: stored.cid,
            size: stored.size, pinnedOn: stored.pinnedOn
        });
        this._log({
            type: ENTRY.TXN_STARTED,
            txId, evidenceId, metadataHash, bundleHash: resolvedBundleHash,
            bundleCid: stored.cid, algorithm, signerSet, timestamp
        });

        // ─── Phase 1: Prepare in parallel with timeout ───────────────────
        const prepareStart = Date.now();
        // Keep the raw promises: a prepare that times out may still land
        // on-chain later and must then be aborted (see _prepareOutcome).
        const rawFabric = this.fabric.prepare({
            txId, evidenceId, metadataHash,
            signerSet, bundleHash: resolvedBundleHash,
            algorithm, targetChain: 'besu'
        });
        const rawBesu = this.besu.prepare({
            txId, evidenceId, metadataHash,
            algorithm, bundleHash: resolvedBundleHash
        });
        rawFabric.catch(() => {});
        rawBesu.catch(() => {});
        const preparePromises = [
            this._withTimeout(rawFabric, this.config.prepareTimeoutMs, 'fabric.prepare'),
            this._withTimeout(rawBesu,   this.config.prepareTimeoutMs, 'besu.prepare')
        ];

        const [fabricPrepare, besuPrepare] = await Promise.allSettled(preparePromises);
        phaseTimings.prepare = Date.now() - prepareStart;

        const fabricOk = fabricPrepare.status === 'fulfilled';
        const besuOk   = besuPrepare.status === 'fulfilled';

        this._log({
            type: fabricOk ? ENTRY.PREPARE_OK : ENTRY.PREPARE_FAILED,
            txId, chain: 'fabric',
            reason: fabricOk ? undefined : (fabricPrepare.reason?.message || String(fabricPrepare.reason))
        });
        this._log({
            type: besuOk ? ENTRY.PREPARE_OK : ENTRY.PREPARE_FAILED,
            txId, chain: 'besu',
            reason: besuOk ? undefined : (besuPrepare.reason?.message || String(besuPrepare.reason))
        });

        // ─── Phase 2: Commit if both ok, else abort ──────────────────────
        const finalizeStart = Date.now();
        if (fabricOk && besuOk) {
            const commitResult = await this._commitBoth(txId);
            phaseTimings.finalize = Date.now() - finalizeStart;
            phaseTimings.total    = Date.now() - t0;

            if (commitResult.ok) {
                this._log({ type: ENTRY.TXN_COMMITTED, txId, phaseTimings });
                return {
                    success: true,
                    outcome: 'COMMITTED',
                    txId,
                    phaseTimings,
                    bundle: { bundleHash: resolvedBundleHash, cid: stored.cid, size: stored.size },
                    details: {
                        fabricPrepare: fabricPrepare.value,
                        besuPrepare:   besuPrepare.value,
                        commit:        commitResult
                    }
                };
            }
            // commit failed irrecoverably; leave for operator / recovery
            this._log({ type: ENTRY.CRITICAL, txId, note: 'commit failed after prepare', detail: commitResult });
            return {
                success: false,
                outcome: 'COMMIT_FAILED',
                txId,
                phaseTimings,
                details: commitResult
            };
        }

        // Prepare failed on at least one chain → abort both
        const reason = `prepare-failure: fabric=${fabricOk ? 'ok' : (fabricPrepare.reason?.message || 'error')}; besu=${besuOk ? 'ok' : (besuPrepare.reason?.message || 'error')}`;
        const [fabricState, besuState] = await Promise.all([
            this._prepareOutcome(fabricPrepare, rawFabric, () => this.fabric.getStatus(txId).then(r => r.result)),
            this._prepareOutcome(besuPrepare,   rawBesu,   () => this.besu.getStatus(txId).then(r => r.statusName))
        ]);
        const abortResult = await this._abortBoth(txId, reason, {
            fabricWasPrepared: fabricState === 'PREPARED',
            besuWasPrepared:   besuState   === 'PREPARED'
        });
        phaseTimings.finalize = Date.now() - finalizeStart;
        phaseTimings.total    = Date.now() - t0;

        if (fabricState === 'UNKNOWN' || besuState === 'UNKNOWN') {
            // A prepare is still in flight: not terminal, so that
            // recoverPendingTransfers() aborts it if it lands later.
            this._log({ type: ENTRY.ABORT_PENDING, txId, reason, fabricState, besuState, phaseTimings });
        } else {
            this._log({ type: ENTRY.TXN_ABORTED, txId, reason, phaseTimings });
        }

        return {
            success: false,
            outcome: 'ABORTED',
            txId,
            reason,
            phaseTimings,
            details: {
                fabricPrepare: fabricOk ? fabricPrepare.value : { error: fabricPrepare.reason?.message },
                besuPrepare:   besuOk   ? besuPrepare.value   : { error: besuPrepare.reason?.message },
                abort:         abortResult
            }
        };
    }

    // ─── Phase 2 helpers ────────────────────────────────────────────────

    /**
     * Whether a chain holds a PREPARED record after a failed prepare phase.
     * A timed-out prepare is not proof of "not prepared": wait up to
     * abortGraceMs for it to settle, then fall back to the on-chain status.
     * @returns {Promise<'PREPARED'|'NOT_PREPARED'|'UNKNOWN'>}
     */
    async _prepareOutcome(settled, raw, queryStatus) {
        if (settled.status === 'fulfilled') return 'PREPARED';
        if (!settled.reason?.timedOut) return 'NOT_PREPARED';
        try {
            await this._withTimeout(raw, this.config.abortGraceMs ?? this.config.prepareTimeoutMs, 'prepare grace');
            return 'PREPARED';
        } catch (e) {
            if (!e.timedOut) return 'NOT_PREPARED';
        }
        try {
            return (await queryStatus()) === 'PREPARED' ? 'PREPARED' : 'UNKNOWN';
        } catch (e) {
            return 'UNKNOWN';
        }
    }

    async _commitBoth(txId) {
        const doFabricCommit = () => this.fabric.commit(txId);
        const doBesuCommit   = () => this.besu.commit(txId);

        const [f, b] = await Promise.allSettled([
            this._withRetries(doFabricCommit, 'fabric.commit'),
            this._withRetries(doBesuCommit,   'besu.commit')
        ]);

        const fabricOk = f.status === 'fulfilled';
        const besuOk   = b.status === 'fulfilled';

        this._log({
            type: fabricOk ? ENTRY.COMMIT_OK : ENTRY.COMMIT_FAILED,
            txId, chain: 'fabric',
            reason: fabricOk ? undefined : (f.reason?.message || String(f.reason))
        });
        this._log({
            type: besuOk ? ENTRY.COMMIT_OK : ENTRY.COMMIT_FAILED,
            txId, chain: 'besu',
            reason: besuOk ? undefined : (b.reason?.message || String(b.reason))
        });

        return {
            ok: fabricOk && besuOk,
            fabric: fabricOk ? f.value : { error: f.reason?.message },
            besu:   besuOk   ? b.value : { error: b.reason?.message }
        };
    }

    async _abortBoth(txId, reason, { fabricWasPrepared, besuWasPrepared }) {
        // Only send abort to chains that actually PREPARED; otherwise the
        // chaincode / contract will revert with "not PREPARED".
        const fabricP = fabricWasPrepared
            ? this._withRetries(() => this.fabric.abort(txId, reason), 'fabric.abort').catch(e => ({ error: e.message }))
            : Promise.resolve({ skipped: true, note: 'fabric was never PREPARED' });

        const besuP = besuWasPrepared
            ? this._withRetries(() => this.besu.abort(txId, reason), 'besu.abort').catch(e => ({ error: e.message }))
            : Promise.resolve({ skipped: true, note: 'besu was never PREPARED' });

        const [f, b] = await Promise.all([fabricP, besuP]);

        this._log({ type: f.error ? ENTRY.ABORT_FAILED : ENTRY.ABORT_OK, txId, chain: 'fabric', detail: f });
        this._log({ type: b.error ? ENTRY.ABORT_FAILED : ENTRY.ABORT_OK, txId, chain: 'besu',   detail: b });

        return { fabric: f, besu: b };
    }

    // ─── Recovery ───────────────────────────────────────────────────────

    /**
     * Replay the coordinator log and resolve any pending (non-terminal)
     * transfers by consulting on-chain state.  Call once at startup.
     *
     * @param {Object}  [opts]
     * @param {boolean} [opts.commitWhenBothPrepared=true] - if true, complete
     *        transfers where both chains PREPARED; if false, abort them.
     * @returns {Promise<Object>} summary of recovered transfers
     */
    async recoverPendingTransfers(opts = {}) {
        const commitWhenBothPrepared = opts.commitWhenBothPrepared !== false;

        const entries = this._readLog();
        const perTxn = new Map();                  // txId → latest entries
        for (const e of entries) {
            if (!e.txId) continue;
            if (!perTxn.has(e.txId)) perTxn.set(e.txId, []);
            perTxn.get(e.txId).push(e);
        }

        const TERMINAL = new Set([ENTRY.TXN_COMMITTED, ENTRY.TXN_ABORTED, ENTRY.TXN_RECOVERED]);
        const pending = [];
        for (const [txId, log] of perTxn) {
            const hasTerminal = log.some(e => TERMINAL.has(e.type));
            if (!hasTerminal) pending.push({ txId, log });
        }

        const resolved = [];
        for (const { txId, log } of pending) {
            try {
                const fabricStatus = await this.fabric.getStatus(txId).then(r => r.result).catch(() => 'NONE');
                const besuStatusObj = await this.besu.getStatus(txId).catch(() => ({ statusName: 'NONE' }));
                const besuStatus = besuStatusObj.statusName;

                const decision = this._decideRecovery(fabricStatus, besuStatus, commitWhenBothPrepared);
                let applied = null;
                if (decision.action === 'commit') {
                    applied = await this._commitBoth(txId);
                } else if (decision.action === 'abort') {
                    applied = await this._abortBoth(txId, 'recovery: ' + decision.reason, {
                        fabricWasPrepared: fabricStatus === 'PREPARED',
                        besuWasPrepared:   besuStatus   === 'PREPARED'
                    });
                }
                this._log({ type: ENTRY.TXN_RECOVERED, txId, fabricStatus, besuStatus, decision, applied });
                resolved.push({ txId, fabricStatus, besuStatus, action: decision.action, ok: true });
            } catch (e) {
                this._log({ type: ENTRY.CRITICAL, txId, note: 'recovery failed', error: e.message });
                resolved.push({ txId, ok: false, error: e.message });
            }
        }

        return {
            scanned: perTxn.size,
            pending: pending.length,
            resolved
        };
    }

    _decideRecovery(fabric, besu, commitIfBoth) {
        if (fabric === 'PREPARED' && besu === 'PREPARED') {
            return commitIfBoth
                ? { action: 'commit', reason: 'both chains PREPARED' }
                : { action: 'abort',  reason: 'both chains PREPARED (policy: abort-on-recover)' };
        }
        if (fabric === 'PREPARED' && besu !== 'PREPARED') {
            return { action: 'abort', reason: `besu is ${besu}; cannot commit half-prepared transfer` };
        }
        if (besu === 'PREPARED' && fabric !== 'PREPARED') {
            return { action: 'abort', reason: `fabric is ${fabric}; cannot commit half-prepared transfer` };
        }
        // Both terminal or both NONE: nothing to do, just record.
        return { action: 'noop', reason: `fabric=${fabric}, besu=${besu}` };
    }

    // ─── Logging ────────────────────────────────────────────────────────

    _log(entry) {
        const record = { ...entry, loggedAt: new Date().toISOString() };
        fs.appendFileSync(this.logPath, JSON.stringify(record) + '\n');
    }

    _readLog() {
        if (!fs.existsSync(this.logPath)) return [];
        return fs.readFileSync(this.logPath, 'utf8')
            .split('\n')
            .filter(Boolean)
            .map(line => {
                try { return JSON.parse(line); } catch { return null; }
            })
            .filter(Boolean);
    }

    // ─── Utility wrappers ───────────────────────────────────────────────

    _withTimeout(promise, ms, label) {
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(
                () => reject(Object.assign(new Error(`${label} timed out after ${ms}ms`), { timedOut: true })),
                ms
            );
        });
        return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    }

    async _withRetries(fn, label) {
        let lastErr;
        for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
            try {
                return await fn();
            } catch (e) {
                lastErr = e;
                if (attempt < this.config.maxRetries) {
                    await new Promise(r => setTimeout(r, this.config.retryBackoffMs * attempt));
                }
            }
        }
        throw new Error(`${label} failed after ${this.config.maxRetries} attempts: ${lastErr?.message || lastErr}`);
    }
}

CompleteCrossChainMesher.ENTRY = ENTRY;

module.exports = CompleteCrossChainMesher;
