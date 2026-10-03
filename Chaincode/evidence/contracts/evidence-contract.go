package contracts

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Evidence represents the structure of the evidence asset with PQC support
type Evidence struct {
	AssetType       string `json:"assetType"`
	EvidenceID      string `json:"evidenceId"`
	Title           string `json:"title"`
	CID             string `json:"cid"`
	MimeType        string `json:"mimeType"`
	OwnerID         string `json:"ownerId"`
	UploaderAddress string `json:"uploaderAddress"`
	Status          string `json:"status"`
	AdditionalInfo  string `json:"additionalInfo,omitempty"`
	
	// Enhanced digital signature fields with algorithm support
	Signature          string `json:"signature,omitempty"`
	SignedDataHash     string `json:"signedDataHash,omitempty"`
	SignatureTimestamp string `json:"signatureTimestamp,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"` // ECC, DILITHIUM2, DILITHIUM3, DILITHIUM5, HYBRID
	
	// PQC Metadata
	SecurityLevel    int    `json:"securityLevel,omitempty"`    // 128, 192, 256 bits
	SignatureSize    int    `json:"signatureSize,omitempty"`    // Size in bytes
	VerificationTime int64  `json:"verificationTime,omitempty"` // Time in milliseconds
	PublicKey        string `json:"publicKey,omitempty"`        // For direct verification
}

// User represents a registered user in the system with PQC support
type User struct {
	AssetType         string `json:"assetType"`
	UserID            string `json:"userId"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PublicKey         string `json:"publicKey"`
	Address           string `json:"address"`
	CreatedAt         string `json:"createdAt"`
	PreferredAlgorithm string `json:"preferredAlgorithm,omitempty"` // ECC, DILITHIUM2, DILITHIUM3, DILITHIUM5
}

// EvidenceContract defines the contract for managing CRUD operations for Evidence and Users with PQC support
type EvidenceContract struct {
	contractapi.Contract
}

// SubmitEvidenceEnhanced submits evidence with digital signature and algorithm selection
func (e *EvidenceContract) SubmitEvidenceEnhanced(ctx contractapi.TransactionContextInterface, 
	evidenceID string, title string, cid string, mimeType string, uploaderAddress string, 
	signature string, signedDataHash string, algorithm string, publicKey string) (string, error) {
	
	// Check if evidence already exists
	exists, err := e.EvidenceExists(ctx, evidenceID)
	if err != nil {
		return "", fmt.Errorf("failed to check if evidence exists: %v", err)
	}
	if exists {
		return "", fmt.Errorf("evidence with ID %s already exists", evidenceID)
	}

	// Verify that uploader is a registered user
	userExists, err := e.UserExists(ctx, uploaderAddress)
	if err != nil {
		return "", fmt.Errorf("failed to verify uploader: %v", err)
	}
	if !userExists {
		return "", fmt.Errorf("uploader address %s is not a registered user", uploaderAddress)
	}

	// Validate algorithm
	if !e.isValidAlgorithm(algorithm) {
		return "", fmt.Errorf("unsupported algorithm: %s. Supported: ECC, DILITHIUM2, DILITHIUM3, DILITHIUM5, HYBRID", algorithm)
	}

	// The chaincode does not verify the signature: it records the signature,
	// the uploader's registered public key and the signed metadata hash, and
	// verification is done by the court / auditor (as described in the paper).
	if signature == "" || signedDataHash == "" {
		return "", fmt.Errorf("signature and signedDataHash are required")
	}
	uploader, err := e.GetUser(ctx, uploaderAddress)
	if err != nil {
		return "", fmt.Errorf("failed to get uploader: %v", err)
	}
	if publicKey != "" && publicKey != uploader.PublicKey {
		return "", fmt.Errorf("publicKey does not match the registered key of %s", uploaderAddress)
	}
	securityLevel := e.getSecurityLevel(algorithm)

	// Use current timestamp
	timestampStr := time.Now().Format(time.RFC3339)

	// Calculate signature size
	signatureSize := len(signature)

	// Create a new evidence record with PQC metadata
	evidence := Evidence{
		AssetType:          "evidence",
		EvidenceID:         evidenceID,
		Title:              title,
		CID:                cid,
		MimeType:           mimeType,
		OwnerID:            "PoliceOrg",
		UploaderAddress:    uploaderAddress,
		Status:             "Submitted",
		Signature:          signature,
		SignedDataHash:     signedDataHash,
		SignatureTimestamp: timestampStr,
		SignatureAlgorithm: algorithm,
		SecurityLevel:      securityLevel,
		SignatureSize:      signatureSize,
		PublicKey:          uploader.PublicKey,
	}

	// Serialize the evidence to JSON
	bytes, err := json.Marshal(evidence)
	if err != nil {
		return "", fmt.Errorf("failed to marshal evidence: %v", err)
	}

	// Store the evidence in the world state
	err = ctx.GetStub().PutState(evidenceID, bytes)
	if err != nil {
		return "", fmt.Errorf("failed to put evidence on the ledger: %v", err)
	}

	// Emit event for monitoring
	eventPayload := map[string]interface{}{
		"evidenceId":      evidenceID,
		"algorithm":       algorithm,
		"securityLevel":   securityLevel,
		"timestamp":       timestampStr,
	}
	eventBytes, _ := json.Marshal(eventPayload)
	err = ctx.GetStub().SetEvent("EvidenceSubmittedEnhanced", eventBytes)
	if err != nil {
		return "", fmt.Errorf("failed to set event: %v", err)
	}

	return fmt.Sprintf("evidence %s successfully added by %s using %s (security: %d-bit)", 
		evidenceID, uploaderAddress, algorithm, securityLevel), nil
}

// QueryEvidenceByAlgorithm retrieves all evidence using a specific algorithm
func (e *EvidenceContract) QueryEvidenceByAlgorithm(ctx contractapi.TransactionContextInterface, algorithm string) ([]Evidence, error) {
	if !e.isValidAlgorithm(algorithm) {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	
	queryString := fmt.Sprintf(`{"selector": {"assetType": "evidence", "signatureAlgorithm": "%s"}}`, algorithm)
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to query evidence by algorithm: %v", err)
	}
	defer resultsIterator.Close()

	var evidenceList []Evidence
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next evidence record: %v", err)
		}

		var evidence Evidence
		err = json.Unmarshal(queryResponse.Value, &evidence)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence record: %v", err)
		}

		evidenceList = append(evidenceList, evidence)
	}

	return evidenceList, nil
}

// GetAlgorithmStatistics returns statistics about algorithm usage
func (e *EvidenceContract) GetAlgorithmStatistics(ctx contractapi.TransactionContextInterface) (map[string]interface{}, error) {
	algorithms := []string{"ECC", "DILITHIUM2", "DILITHIUM3", "DILITHIUM5", "HYBRID"}
	stats := make(map[string]interface{})
	
	totalCount := 0
	for _, algo := range algorithms {
		evidenceList, err := e.QueryEvidenceByAlgorithm(ctx, algo)
		if err != nil {
			continue // Skip if error for this algorithm
		}
		
		stats[algo] = map[string]interface{}{
			"count": len(evidenceList),
			"securityLevel": e.getSecurityLevel(algo),
			"recommendation": e.getAlgorithmRecommendation(algo),
		}
		totalCount += len(evidenceList)
	}
	
	stats["totalEvidence"] = totalCount
	stats["timestamp"] = time.Now().Format(time.RFC3339)
	
	return stats, nil
}

// RegisterUserEnhanced registers a user with preferred algorithm
func (e *EvidenceContract) RegisterUserEnhanced(ctx contractapi.TransactionContextInterface, 
	name string, email string, publicKey string, address string, createdAt string, preferredAlgorithm string) (string, error) {
	
	// Check if user already exists
	userKey := "user_" + address
	exists, err := e.UserExists(ctx, address)
	if err != nil {
		return "", fmt.Errorf("failed to check if user exists: %v", err)
	}
	if exists {
		return "", fmt.Errorf("user with address %s already exists", address)
	}

	// Validate preferred algorithm
	if preferredAlgorithm != "" && !e.isValidAlgorithm(preferredAlgorithm) {
		return "", fmt.Errorf("unsupported preferred algorithm: %s", preferredAlgorithm)
	}

	// Create a new user
	user := User{
		AssetType:         "user",
		UserID:            address,
		Name:              name,
		Email:             email,
		PublicKey:         publicKey,
		Address:           address,
		CreatedAt:         createdAt,
		PreferredAlgorithm: preferredAlgorithm,
	}

	// Serialize the user to JSON
	bytes, err := json.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user: %v", err)
	}

	// Store the user in the world state
	err = ctx.GetStub().PutState(userKey, bytes)
	if err != nil {
		return "", fmt.Errorf("failed to put user on the ledger: %v", err)
	}

	return fmt.Sprintf("user %s successfully registered with preferred algorithm %s", address, preferredAlgorithm), nil
}

// Utility function to validate algorithm
func (e *EvidenceContract) isValidAlgorithm(algorithm string) bool {
	validAlgorithms := map[string]bool{
		"ECC":        true,
		"DILITHIUM2": true,
		"DILITHIUM3": true,
		"DILITHIUM5": true,
		"HYBRID":     true,
	}
	return validAlgorithms[algorithm]
}

// Utility function to get security level
func (e *EvidenceContract) getSecurityLevel(algorithm string) int {
	securityLevels := map[string]int{
		"ECC":        128,
		"DILITHIUM2": 128,
		"DILITHIUM3": 192,
		"DILITHIUM5": 256,
		"HYBRID":     192,
	}
	return securityLevels[algorithm]
}

// Utility function to get algorithm recommendation
func (e *EvidenceContract) getAlgorithmRecommendation(algorithm string) string {
	recommendations := map[string]string{
		"ECC":        "Classical cryptography - vulnerable to quantum attacks",
		"DILITHIUM2": "Good balance for most applications",
		"DILITHIUM3": "Recommended optimal balance",
		"DILITHIUM5": "Maximum security - higher resource usage",
		"HYBRID":     "Transition strategy - both ECC and PQC",
	}
	return recommendations[algorithm]
}

// ========== KEEP ALL YOUR EXISTING METHODS BELOW ==========

// SubmitEvidence submits evidence with digital signature (original method - keep for backward compatibility)
func (e *EvidenceContract) SubmitEvidence(ctx contractapi.TransactionContextInterface, evidenceID string, title string, cid string, mimeType string, uploaderAddress string, signature string, signedDataHash string) (string, error) {
	// Check if evidence already exists
	exists, err := e.EvidenceExists(ctx, evidenceID)
	if err != nil {
		return "", fmt.Errorf("failed to check if evidence exists: %v", err)
	}
	if exists {
		return "", fmt.Errorf("evidence with ID %s already exists", evidenceID)
	}

	// Verify that uploader is a registered user
	userExists, err := e.UserExists(ctx, uploaderAddress)
	if err != nil {
		return "", fmt.Errorf("failed to verify uploader: %v", err)
	}
	if !userExists {
		return "", fmt.Errorf("uploader address %s is not a registered user", uploaderAddress)
	}

	// Use current timestamp
	timestampStr := time.Now().Format(time.RFC3339)

	// Get user to retrieve public key for backward compatibility
	user, err := e.GetUser(ctx, uploaderAddress)
	if err != nil {
		return "", fmt.Errorf("failed to get user details: %v", err)
	}

	// Calculate signature size for backward compatibility
	signatureSize := len(signature)
	if signatureSize == 0 {
		signatureSize = 72 // Default ECC signature size
	}

	// Create a new evidence record with default PQC values for backward compatibility
	evidence := Evidence{
		AssetType:          "evidence",
		EvidenceID:         evidenceID,
		Title:              title,
		CID:                cid,
		MimeType:           mimeType,
		OwnerID:            "PoliceOrg",
		UploaderAddress:    uploaderAddress,
		Status:             "Submitted",
		Signature:          signature,
		SignedDataHash:     signedDataHash,
		SignatureTimestamp: timestampStr,
		SignatureAlgorithm: "ECC", // Default to ECC for backward compatibility
		SecurityLevel:      128,   // Default security level for ECC
		SignatureSize:      signatureSize,
		VerificationTime:   1,     // Default verification time for ECC
		PublicKey:          user.PublicKey, // Use user's public key
	}

	// Serialize the evidence to JSON
	bytes, err := json.Marshal(evidence)
	if err != nil {
		return "", fmt.Errorf("failed to marshal evidence: %v", err)
	}

	// Store the evidence in the world state
	err = ctx.GetStub().PutState(evidenceID, bytes)
	if err != nil {
		return "", fmt.Errorf("failed to put evidence on the ledger: %v", err)
	}

	return fmt.Sprintf("evidence %s successfully added by %s", evidenceID, uploaderAddress), nil
}

// UserExists checks if user with the given address exists
func (e *EvidenceContract) UserExists(ctx contractapi.TransactionContextInterface, userAddress string) (bool, error) {
	userKey := "user_" + userAddress
	data, err := ctx.GetStub().GetState(userKey)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return data != nil, nil
}

// RegisterUser adds a new user to the ledger (original method - keep for backward compatibility)
func (e *EvidenceContract) RegisterUser(ctx contractapi.TransactionContextInterface, name string, email string, publicKey string, address string, createdAt string) (string, error) {
	// Check if user already exists
	userKey := "user_" + address
	exists, err := e.UserExists(ctx, address)
	if err != nil {
		return "", fmt.Errorf("failed to check if user exists: %v", err)
	}
	if exists {
		return "", fmt.Errorf("user with address %s already exists", address)
	}

	// Create a new user with default algorithm for backward compatibility
	user := User{
		AssetType:         "user",
		UserID:            address,
		Name:              name,
		Email:             email,
		PublicKey:         publicKey,
		Address:           address,
		CreatedAt:         createdAt,
		PreferredAlgorithm: "ECC", // Default algorithm for backward compatibility
	}

	// Serialize the user to JSON
	bytes, err := json.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user: %v", err)
	}

	// Store the user in the world state
	err = ctx.GetStub().PutState(userKey, bytes)
	if err != nil {
		return "", fmt.Errorf("failed to put user on the ledger: %v", err)
	}

	return fmt.Sprintf("user %s successfully registered", address), nil
}

// GetUser retrieves a user by their address
func (e *EvidenceContract) GetUser(ctx contractapi.TransactionContextInterface, userAddress string) (*User, error) {
	userKey := "user_" + userAddress
	bytes, err := ctx.GetStub().GetState(userKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("user with address %s does not exist", userAddress)
	}

	var user User
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal user data: %v", err)
	}

	return &user, nil
}

// GetAllUsers retrieves all registered users
func (e *EvidenceContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]User, error) {
	queryString := `{"selector": {"assetType": "user"}}`
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to query all users: %v", err)
	}
	defer resultsIterator.Close()

	var users []User
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next user record: %v", err)
		}

		var user User
		err = json.Unmarshal(queryResponse.Value, &user)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal user record: %v", err)
		}

		users = append(users, user)
	}

	return users, nil
}

// EvidenceExists checks if evidence with the given ID exists in the world state
func (e *EvidenceContract) EvidenceExists(ctx contractapi.TransactionContextInterface, evidenceID string) (bool, error) {
	data, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return data != nil, nil
}

// ReadEvidence retrieves an evidence record by its ID
func (e *EvidenceContract) ReadEvidence(ctx contractapi.TransactionContextInterface, evidenceID string) (*Evidence, error) {
	bytes, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("evidence with ID %s does not exist", evidenceID)
	}

	var evidence Evidence
	err = json.Unmarshal(bytes, &evidence)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal world state data to type Evidence: %v", err)
	}

	// Set default values for backward compatibility if fields are empty
	if evidence.AdditionalInfo == "" {
		evidence.AdditionalInfo = "No additional info provided."
	}
	if evidence.SignatureAlgorithm == "" {
		evidence.SignatureAlgorithm = "ECC"
	}
	if evidence.SecurityLevel == 0 {
		evidence.SecurityLevel = 128
	}
	if evidence.SignatureSize == 0 {
		evidence.SignatureSize = len(evidence.Signature)
		if evidence.SignatureSize == 0 {
			evidence.SignatureSize = 72 // Default ECC size
		}
	}
	if evidence.VerificationTime == 0 {
		evidence.VerificationTime = 1 // Default ECC verification time
	}
	if evidence.PublicKey == "" {
		// Try to get public key from user
		user, err := e.GetUser(ctx, evidence.UploaderAddress)
		if err == nil {
			evidence.PublicKey = user.PublicKey
		}
	}

	return &evidence, nil
}

// UpdateEvidence updates the status and additional info of an evidence record
func (e *EvidenceContract) UpdateEvidence(ctx contractapi.TransactionContextInterface, evidenceID string, newStatus string, additionalInfo string) error {
	evidenceAsBytes, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if evidenceAsBytes == nil {
		return fmt.Errorf("evidence with ID %s does not exist", evidenceID)
	}

	var evidence Evidence
	err = json.Unmarshal(evidenceAsBytes, &evidence)
	if err != nil {
		return fmt.Errorf("could not unmarshal evidence: %v", err)
	}

	evidence.Status = newStatus
	evidence.AdditionalInfo = additionalInfo

	updatedEvidenceAsBytes, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal updated evidence: %v", err)
	}

	err = ctx.GetStub().PutState(evidenceID, updatedEvidenceAsBytes)
	if err != nil {
		return fmt.Errorf("failed to update evidence on ledger: %v", err)
	}

	return nil
}

// DeleteEvidence deletes an evidence record by its ID
func (e *EvidenceContract) DeleteEvidence(ctx contractapi.TransactionContextInterface, evidenceID string) error {
	evidenceAsBytes, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if evidenceAsBytes == nil {
		return fmt.Errorf("evidence with ID %s does not exist", evidenceID)
	}

	err = ctx.GetStub().DelState(evidenceID)
	if err != nil {
		return fmt.Errorf("failed to delete evidence from ledger: %v", err)
	}

	return nil
}

// TransferOwnership allows transferring ownership of evidence to another organization
func (e *EvidenceContract) TransferOwnership(ctx contractapi.TransactionContextInterface, evidenceID string, newOwner string) error {
	evidenceAsBytes, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if evidenceAsBytes == nil {
		return fmt.Errorf("evidence with ID %s does not exist", evidenceID)
	}

	var evidence Evidence
	err = json.Unmarshal(evidenceAsBytes, &evidence)
	if err != nil {
		return fmt.Errorf("failed to unmarshal evidence: %v", err)
	}

	evidence.OwnerID = newOwner

	updatedEvidenceAsBytes, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal updated evidence: %v", err)
	}

	err = ctx.GetStub().PutState(evidenceID, updatedEvidenceAsBytes)
	if err != nil {
		return fmt.Errorf("failed to transfer ownership: %v", err)
	}

	return nil
}

// GetAllEvidence retrieves all evidence records from the ledger
func (e *EvidenceContract) GetAllEvidence(ctx contractapi.TransactionContextInterface) ([]Evidence, error) {
	queryString := `{"selector": {"assetType": "evidence"}}`
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to query all evidence: %v", err)
	}
	defer resultsIterator.Close()

	var evidenceList []Evidence
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next evidence record: %v", err)
		}

		var evidence Evidence
		err = json.Unmarshal(queryResponse.Value, &evidence)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence record: %v", err)
		}

		// Set default values for backward compatibility
		if evidence.AdditionalInfo == "" {
			evidence.AdditionalInfo = "No additional information provided."
		}
		if evidence.SignatureAlgorithm == "" {
			evidence.SignatureAlgorithm = "ECC"
		}
		if evidence.SecurityLevel == 0 {
			evidence.SecurityLevel = 128
		}
		if evidence.SignatureSize == 0 {
			evidence.SignatureSize = len(evidence.Signature)
			if evidence.SignatureSize == 0 {
				evidence.SignatureSize = 72
			}
		}
		if evidence.VerificationTime == 0 {
			evidence.VerificationTime = 1
		}
		if evidence.PublicKey == "" {
			// Try to get public key from user
			user, err := e.GetUser(ctx, evidence.UploaderAddress)
			if err == nil {
				evidence.PublicKey = user.PublicKey
			}
		}

		evidenceList = append(evidenceList, evidence)
	}

	return evidenceList, nil
}