package contracts

// ─── evidence-transfer.go ────────────────────────────────────────────────
//
// 2PC transfer methods for the EvidenceContract.
//
// This file ADDS methods to the existing EvidenceContract struct.  It
// does NOT modify evidence-contract.go.  Go compiles all files in a
// package together, so PrepareTransfer / CommitTransfer / AbortTransfer /
// GetTransferStatus / GetTransfer become available on the same chaincode.
//
// Design:
//   - Each 2PC transfer has a unique txID chosen by the off-chain
//     coordinator (typically H(evidenceID || timestamp || metadataHash)).
//   - PrepareTransfer locks the target evidence (so two concurrent
//     transfers of the same evidence cannot both proceed) and creates a
//     transfer record in state PREPARED.
//   - CommitTransfer transitions PREPARED → COMMITTED and releases the
//     evidence lock.  Idempotent: committing an already-COMMITTED
//     transfer returns success.
//   - AbortTransfer transitions PREPARED → ABORTED and releases the
//     evidence lock.  Idempotent: aborting an already-ABORTED transfer
//     returns success.
//   - Terminal states are irreversible: commit on ABORTED reverts,
//     abort on COMMITTED reverts.
//
// Storage layout:
//   "transfer_<txID>"        → CrossChainTransfer JSON
//   "lock_<evidenceID>"      → txID (bytes) of the pending transfer
//                              (present only while status == PREPARED)

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ─── CrossChainTransfer ──────────────────────────────────────────────────

// CrossChainTransfer is the 2PC transfer record stored on Fabric.
type CrossChainTransfer struct {
	AssetType    string   `json:"assetType"`    // always "crossChainTransfer"
	TxID         string   `json:"txId"`         // unique transfer identifier
	EvidenceID   string   `json:"evidenceId"`   // target evidence
	MetadataHash string   `json:"metadataHash"` // hex SHA-256 of metadata
	SignerSet    []string `json:"signerSet"`    // addresses that signed the multi-sig bundle
	BundleHash   string   `json:"bundleHash"`   // hex SHA-256 of the canonical multi-sig bundle (bundle stored off-chain)
	Algorithm    string   `json:"algorithm"`    // ECC | DILITHIUM2 | DILITHIUM3 | DILITHIUM5
	SourceChain  string   `json:"sourceChain"`  // always "fabric"
	TargetChain  string   `json:"targetChain"`  // e.g. "besu"
	Status       string   `json:"status"`       // PREPARED | COMMITTED | ABORTED
	PreparedAt   string   `json:"preparedAt"`
	CommittedAt  string   `json:"committedAt,omitempty" metadata:",optional"`
	AbortedAt    string   `json:"abortedAt,omitempty" metadata:",optional"`
	AbortReason  string   `json:"abortReason,omitempty" metadata:",optional"`
}

// ─── Status constants ────────────────────────────────────────────────────

const (
	StatusPrepared  = "PREPARED"
	StatusCommitted = "COMMITTED"
	StatusAborted   = "ABORTED"
	StatusNone      = "NONE"
)

// ─── Event names ─────────────────────────────────────────────────────────

const (
	EventTransferPrepared  = "TransferPrepared"
	EventTransferCommitted = "TransferCommitted"
	EventTransferAborted   = "TransferAborted"
)

// ─── Storage key helpers ─────────────────────────────────────────────────

func transferKey(txID string) string    { return "transfer_" + txID }
func evidenceLockKey(eID string) string { return "lock_" + eID }

// ─── PrepareTransfer ─────────────────────────────────────────────────────
//
// Phase 1 of 2PC.  Locks the evidence and records a PREPARED transfer.
//
// Rejects if:
//   - any required argument is empty
//   - signerSet JSON is malformed or empty
//   - evidenceID does not exist
//   - evidence is already locked by a different pending transfer
//   - txID already exists with different parameters
//
// Idempotent: re-preparing the same txID with identical args in PREPARED
// state returns success (used for coordinator retries).
func (e *EvidenceContract) PrepareTransfer(
	ctx contractapi.TransactionContextInterface,
	txID string,
	evidenceID string,
	metadataHash string,
	signerSetJSON string,
	bundleHash string,
	algorithm string,
	targetChain string,
) (string, error) {
	// Input validation
	if txID == "" || evidenceID == "" || metadataHash == "" || bundleHash == "" {
		return "", fmt.Errorf("PrepareTransfer: txID, evidenceID, metadataHash, bundleHash required")
	}
	if !e.isValidAlgorithm(algorithm) {
		return "", fmt.Errorf("PrepareTransfer: unsupported algorithm %s", algorithm)
	}

	var signerSet []string
	if err := json.Unmarshal([]byte(signerSetJSON), &signerSet); err != nil {
		return "", fmt.Errorf("PrepareTransfer: invalid signerSet JSON: %v", err)
	}
	if len(signerSet) == 0 {
		return "", fmt.Errorf("PrepareTransfer: signerSet must be non-empty")
	}

	// Evidence must exist
	exists, err := e.EvidenceExists(ctx, evidenceID)
	if err != nil {
		return "", fmt.Errorf("PrepareTransfer: check evidence: %v", err)
	}
	if !exists {
		return "", fmt.Errorf("PrepareTransfer: evidence %s does not exist", evidenceID)
	}

	// Idempotency check
	tKey := transferKey(txID)
	existingBytes, err := ctx.GetStub().GetState(tKey)
	if err != nil {
		return "", fmt.Errorf("PrepareTransfer: read existing: %v", err)
	}
	if existingBytes != nil {
		var existing CrossChainTransfer
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return "", fmt.Errorf("PrepareTransfer: corrupted existing record: %v", err)
		}
		if existing.Status == StatusPrepared &&
			existing.EvidenceID == evidenceID &&
			existing.MetadataHash == metadataHash &&
			existing.BundleHash == bundleHash &&
			existing.Algorithm == algorithm {
			// Same prepare, already done — idempotent success
			return existing.Status, nil
		}
		return "", fmt.Errorf("PrepareTransfer: txID %s already exists with status %s", txID, existing.Status)
	}

	// Evidence lock check
	lKey := evidenceLockKey(evidenceID)
	lockBytes, err := ctx.GetStub().GetState(lKey)
	if err != nil {
		return "", fmt.Errorf("PrepareTransfer: check lock: %v", err)
	}
	if lockBytes != nil {
		return "", fmt.Errorf("PrepareTransfer: evidence %s is locked by pending transfer %s",
			evidenceID, string(lockBytes))
	}

	// Create transfer record
	now := time.Now().Format(time.RFC3339)
	transfer := CrossChainTransfer{
		AssetType:    "crossChainTransfer",
		TxID:         txID,
		EvidenceID:   evidenceID,
		MetadataHash: metadataHash,
		SignerSet:    signerSet,
		BundleHash:   bundleHash,
		Algorithm:    algorithm,
		SourceChain:  "fabric",
		TargetChain:  targetChain,
		Status:       StatusPrepared,
		PreparedAt:   now,
	}

	transferBytes, err := json.Marshal(transfer)
	if err != nil {
		return "", fmt.Errorf("PrepareTransfer: marshal: %v", err)
	}
	if err := ctx.GetStub().PutState(tKey, transferBytes); err != nil {
		return "", fmt.Errorf("PrepareTransfer: put transfer: %v", err)
	}
	if err := ctx.GetStub().PutState(lKey, []byte(txID)); err != nil {
		return "", fmt.Errorf("PrepareTransfer: put lock: %v", err)
	}

	// Event
	payload := map[string]interface{}{
		"txId":         txID,
		"evidenceId":   evidenceID,
		"metadataHash": metadataHash,
		"bundleHash":   bundleHash,
		"algorithm":    algorithm,
		"targetChain":  targetChain,
		"preparedAt":   now,
	}
	payloadBytes, _ := json.Marshal(payload)
	if err := ctx.GetStub().SetEvent(EventTransferPrepared, payloadBytes); err != nil {
		return "", fmt.Errorf("PrepareTransfer: set event: %v", err)
	}

	return StatusPrepared, nil
}

// ─── CommitTransfer ──────────────────────────────────────────────────────
//
// Phase 2 of 2PC (success path).  PREPARED → COMMITTED.  Idempotent.
func (e *EvidenceContract) CommitTransfer(
	ctx contractapi.TransactionContextInterface,
	txID string,
) (string, error) {
	if txID == "" {
		return "", fmt.Errorf("CommitTransfer: txID required")
	}

	tKey := transferKey(txID)
	bytes, err := ctx.GetStub().GetState(tKey)
	if err != nil {
		return "", fmt.Errorf("CommitTransfer: read: %v", err)
	}
	if bytes == nil {
		return "", fmt.Errorf("CommitTransfer: no transfer with txID %s", txID)
	}

	var transfer CrossChainTransfer
	if err := json.Unmarshal(bytes, &transfer); err != nil {
		return "", fmt.Errorf("CommitTransfer: unmarshal: %v", err)
	}

	// Idempotent
	if transfer.Status == StatusCommitted {
		return StatusCommitted, nil
	}
	// Cannot un-abort
	if transfer.Status == StatusAborted {
		return "", fmt.Errorf("CommitTransfer: transfer %s is ABORTED; cannot commit", txID)
	}
	if transfer.Status != StatusPrepared {
		return "", fmt.Errorf("CommitTransfer: transfer %s in unexpected state %s", txID, transfer.Status)
	}

	// State transition
	now := time.Now().Format(time.RFC3339)
	transfer.Status = StatusCommitted
	transfer.CommittedAt = now

	updated, err := json.Marshal(transfer)
	if err != nil {
		return "", fmt.Errorf("CommitTransfer: marshal: %v", err)
	}
	if err := ctx.GetStub().PutState(tKey, updated); err != nil {
		return "", fmt.Errorf("CommitTransfer: put: %v", err)
	}
	// Release evidence lock
	if err := ctx.GetStub().DelState(evidenceLockKey(transfer.EvidenceID)); err != nil {
		return "", fmt.Errorf("CommitTransfer: release lock: %v", err)
	}

	// Event
	payload := map[string]interface{}{
		"txId":        txID,
		"evidenceId":  transfer.EvidenceID,
		"committedAt": now,
	}
	payloadBytes, _ := json.Marshal(payload)
	_ = ctx.GetStub().SetEvent(EventTransferCommitted, payloadBytes)

	return StatusCommitted, nil
}

// ─── AbortTransfer ───────────────────────────────────────────────────────
//
// Phase 2 of 2PC (failure path).  PREPARED → ABORTED.  Idempotent.
func (e *EvidenceContract) AbortTransfer(
	ctx contractapi.TransactionContextInterface,
	txID string,
	reason string,
) (string, error) {
	if txID == "" {
		return "", fmt.Errorf("AbortTransfer: txID required")
	}

	tKey := transferKey(txID)
	bytes, err := ctx.GetStub().GetState(tKey)
	if err != nil {
		return "", fmt.Errorf("AbortTransfer: read: %v", err)
	}
	if bytes == nil {
		return "", fmt.Errorf("AbortTransfer: no transfer with txID %s", txID)
	}

	var transfer CrossChainTransfer
	if err := json.Unmarshal(bytes, &transfer); err != nil {
		return "", fmt.Errorf("AbortTransfer: unmarshal: %v", err)
	}

	// Idempotent
	if transfer.Status == StatusAborted {
		return StatusAborted, nil
	}
	// Cannot un-commit
	if transfer.Status == StatusCommitted {
		return "", fmt.Errorf("AbortTransfer: transfer %s is COMMITTED; cannot abort", txID)
	}
	if transfer.Status != StatusPrepared {
		return "", fmt.Errorf("AbortTransfer: transfer %s in unexpected state %s", txID, transfer.Status)
	}

	// State transition
	now := time.Now().Format(time.RFC3339)
	transfer.Status = StatusAborted
	transfer.AbortedAt = now
	transfer.AbortReason = reason

	updated, err := json.Marshal(transfer)
	if err != nil {
		return "", fmt.Errorf("AbortTransfer: marshal: %v", err)
	}
	if err := ctx.GetStub().PutState(tKey, updated); err != nil {
		return "", fmt.Errorf("AbortTransfer: put: %v", err)
	}
	// Release evidence lock
	if err := ctx.GetStub().DelState(evidenceLockKey(transfer.EvidenceID)); err != nil {
		return "", fmt.Errorf("AbortTransfer: release lock: %v", err)
	}

	// Event
	payload := map[string]interface{}{
		"txId":       txID,
		"evidenceId": transfer.EvidenceID,
		"reason":     reason,
		"abortedAt":  now,
	}
	payloadBytes, _ := json.Marshal(payload)
	_ = ctx.GetStub().SetEvent(EventTransferAborted, payloadBytes)

	return StatusAborted, nil
}

// ─── GetTransferStatus ───────────────────────────────────────────────────
//
// Returns "PREPARED" | "COMMITTED" | "ABORTED" | "NONE".  Used by the
// off-chain coordinator for crash recovery.
func (e *EvidenceContract) GetTransferStatus(
	ctx contractapi.TransactionContextInterface,
	txID string,
) (string, error) {
	bytes, err := ctx.GetStub().GetState(transferKey(txID))
	if err != nil {
		return "", fmt.Errorf("GetTransferStatus: read: %v", err)
	}
	if bytes == nil {
		return StatusNone, nil
	}
	var transfer CrossChainTransfer
	if err := json.Unmarshal(bytes, &transfer); err != nil {
		return "", fmt.Errorf("GetTransferStatus: unmarshal: %v", err)
	}
	return transfer.Status, nil
}

// ─── GetTransfer ─────────────────────────────────────────────────────────
//
// Returns the full CrossChainTransfer record.  Used by auditors and the
// coordinator for detailed inspection.
func (e *EvidenceContract) GetTransfer(
	ctx contractapi.TransactionContextInterface,
	txID string,
) (*CrossChainTransfer, error) {
	bytes, err := ctx.GetStub().GetState(transferKey(txID))
	if err != nil {
		return nil, fmt.Errorf("GetTransfer: read: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("GetTransfer: no transfer with txID %s", txID)
	}
	var transfer CrossChainTransfer
	if err := json.Unmarshal(bytes, &transfer); err != nil {
		return nil, fmt.Errorf("GetTransfer: unmarshal: %v", err)
	}
	return &transfer, nil
}
