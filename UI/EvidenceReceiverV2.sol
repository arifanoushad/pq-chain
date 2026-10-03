// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title   EvidenceReceiverV2
 * @notice  Two-phase-commit (2PC) evidence receiver for cross-chain forensic
 *          transfers.  Besu-side counterpart to the Hyperledger Fabric
 *          EvidenceContract.PrepareTransfer / CommitTransfer / AbortTransfer
 *          methods.
 *
 * ─── State machine ──────────────────────────────────────────────────────
 *    NONE ── prepare ──►  PREPARED ── commit ──►  COMMITTED (terminal)
 *                             │
 *                             └── abortTransfer ──►  ABORTED (terminal)
 *
 * Terminal states are irreversible:
 *   - commit on ABORTED reverts
 *   - abortTransfer on COMMITTED reverts
 * Terminal states are idempotent:
 *   - commit on COMMITTED returns silently
 *   - abortTransfer on ABORTED returns silently
 *
 * ─── Storage layout ─────────────────────────────────────────────────────
 * Only a commitment to the multi-signature bundle is stored on-chain
 * (`bundleHash` = SHA-256 of the canonical bundle bytes).  The bundle
 * itself is not in calldata or events: the coordinator stores it off-chain
 * (IPFS pin + archive, see UI/utils/bundleStore.js) before calling
 * prepare, and auditors fetch it by bundleHash.  Per-transfer on-chain
 * data is therefore independent of the threshold t.
 *
 * ─── Access control ─────────────────────────────────────────────────────
 * A single `coordinator` address (the off-chain 2PC coordinator / mesher)
 * is authorised to drive state transitions.  The deployer is the initial
 * coordinator; the role can be rotated.
 */
contract EvidenceReceiverV2 {

    enum Status { NONE, PREPARED, COMMITTED, ABORTED }

    struct Transfer {
        string  evidenceId;
        bytes32 metadataHash;
        bytes32 bundleHash;
        string  algorithm;
        Status  status;
        uint256 preparedAt;
        uint256 committedAt;
        uint256 abortedAt;
        string  abortReason;
    }

    mapping(bytes32 => Transfer) public transfers;

    address public coordinator;

    // ─── Events ─────────────────────────────────────────────────────────
    event Prepared(
        bytes32 indexed txId,
        string  evidenceId,
        bytes32 metadataHash,
        bytes32 bundleHash,
        string  algorithm,
        uint256 preparedAt
    );
    event Committed(bytes32 indexed txId, uint256 committedAt);
    event Aborted(bytes32 indexed txId, uint256 abortedAt, string reason);
    event CoordinatorRotated(address indexed from, address indexed to);

    // ─── Modifiers ──────────────────────────────────────────────────────
    modifier onlyCoordinator() {
        require(msg.sender == coordinator, "EvidenceReceiverV2: not coordinator");
        _;
    }

    constructor() {
        coordinator = msg.sender;
    }

    // ─── Phase 1: prepare ───────────────────────────────────────────────
    /**
     * Record a PREPARED transfer.  Reverts if a transfer with this txId
     * already exists (the off-chain coordinator must deduplicate).
     *
     * @param txId          coordinator-chosen 32-byte transfer identifier
     * @param evidenceId    evidence reference (e.g. "CASE-001")
     * @param metadataHash  SHA-256 of the evidence metadata (binds CID + fields)
     * @param algorithm     "ECC" | "DILITHIUM2" | "DILITHIUM3" | "DILITHIUM5"
     * @param bundleHash    SHA-256 of the canonical multi-signature bundle bytes
     */
    function prepare(
        bytes32 txId,
        string calldata evidenceId,
        bytes32 metadataHash,
        string calldata algorithm,
        bytes32 bundleHash
    ) external onlyCoordinator {
        require(transfers[txId].status == Status.NONE, "EvidenceReceiverV2: transfer exists");
        require(bytes(evidenceId).length > 0,         "EvidenceReceiverV2: empty evidenceId");
        require(bytes(algorithm).length > 0,          "EvidenceReceiverV2: empty algorithm");
        require(metadataHash != bytes32(0),           "EvidenceReceiverV2: zero metadataHash");
        require(bundleHash   != bytes32(0),           "EvidenceReceiverV2: zero bundleHash");

        transfers[txId] = Transfer({
            evidenceId:   evidenceId,
            metadataHash: metadataHash,
            bundleHash:   bundleHash,
            algorithm:    algorithm,
            status:       Status.PREPARED,
            preparedAt:   block.timestamp,
            committedAt:  0,
            abortedAt:    0,
            abortReason:  ""
        });

        emit Prepared(txId, evidenceId, metadataHash, bundleHash, algorithm, block.timestamp);
    }

    // ─── Phase 2 success: commit ────────────────────────────────────────
    function commit(bytes32 txId) external onlyCoordinator {
        Transfer storage t = transfers[txId];

        if (t.status == Status.COMMITTED) { return; }                   // idempotent
        require(t.status == Status.PREPARED, "EvidenceReceiverV2: not in PREPARED state");

        t.status      = Status.COMMITTED;
        t.committedAt = block.timestamp;

        emit Committed(txId, block.timestamp);
    }

    // ─── Phase 2 failure: abort ─────────────────────────────────────────
    function abortTransfer(bytes32 txId, string calldata reason) external onlyCoordinator {
        Transfer storage t = transfers[txId];

        if (t.status == Status.ABORTED) { return; }                     // idempotent
        require(t.status == Status.PREPARED, "EvidenceReceiverV2: not in PREPARED state");

        t.status      = Status.ABORTED;
        t.abortedAt   = block.timestamp;
        t.abortReason = reason;

        emit Aborted(txId, block.timestamp, reason);
    }

    // ─── Views ──────────────────────────────────────────────────────────
    /// Current status; returns NONE for unknown txIds.
    function getStatus(bytes32 txId) external view returns (Status) {
        return transfers[txId].status;
    }

    /// Full record (all fields).
    function getTransfer(bytes32 txId) external view returns (
        string memory evidenceId,
        bytes32 metadataHash,
        bytes32 bundleHash,
        string memory algorithm,
        Status status,
        uint256 preparedAt,
        uint256 committedAt,
        uint256 abortedAt,
        string memory abortReason
    ) {
        Transfer storage t = transfers[txId];
        return (
            t.evidenceId,
            t.metadataHash,
            t.bundleHash,
            t.algorithm,
            t.status,
            t.preparedAt,
            t.committedAt,
            t.abortedAt,
            t.abortReason
        );
    }

    // ─── Coordinator rotation ───────────────────────────────────────────
    function rotateCoordinator(address newCoordinator) external onlyCoordinator {
        require(newCoordinator != address(0), "EvidenceReceiverV2: zero address");
        address previous = coordinator;
        coordinator      = newCoordinator;
        emit CoordinatorRotated(previous, newCoordinator);
    }
}
