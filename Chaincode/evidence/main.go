package main

import (
	"evidence/contracts" // Correct import path
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	// Create a new instance of the EvidenceContract
	evidenceContract := new(contracts.EvidenceContract)

	// Create the chaincode from the EvidenceContract
	chaincode, err := contractapi.NewChaincode(evidenceContract)

	if err != nil {
		// Log and panic if the chaincode could not be created
		log.Panicf("Could not create chaincode : %v", err)
	}

	// Chaincode-as-a-service (Fabric ccaas_builder): when CHAINCODE_SERVER_ADDRESS
	// is set, the chaincode runs as a server that the peer connects to, with
	// CHAINCODE_ID set to the installed package ID. Otherwise the peer builds and
	// launches it as usual.
	if address := os.Getenv("CHAINCODE_SERVER_ADDRESS"); address != "" {
		server := &shim.ChaincodeServer{
			CCID:     os.Getenv("CHAINCODE_ID"),
			Address:  address,
			CC:       chaincode,
			TLSProps: shim.TLSProperties{Disabled: true},
		}
		if err := server.Start(); err != nil {
			log.Panicf("Failed to start chaincode server : %v", err)
		}
		return
	}

	// Start the chaincode
	err = chaincode.Start()

	if err != nil {
		// Log and panic if the chaincode could not be started
		log.Panicf("Failed to start chaincode : %v", err)
	}
}
