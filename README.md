# PQ-Chain: A Post-Quantum Attributable Signature-Bundle Protocol with Two-Phase Commit for Cross-Chain Digital Forensic Evidence Transfer

Reference implementation accompanying:

> **PQ-Chain: A Post-Quantum Attributable Signature-Bundle Protocol with Two-Phase Commit for Cross-Chain Digital Forensic Evidence Transfer**
> Arifa P, Jithesh K, Syamkrishnan M.S.
> *Under review at Journal of Information Security and Applications (Elsevier)*

This repository contains the implementation that produces every empirical number in the revised paper (tag `jisa-r1`). All reported measurements were taken with the coordinator driving a live Hyperledger Fabric 2.4.8 network and a live Hyperledger Besu node; no Fabric stub is used in any reported result. The raw outputs of every run are in `UI/test-scripts/test-results/revision/`.

---

## Table of Contents

1. [What this is](#what-this-is)
2. [What's in this repository](#whats-in-this-repository)
3. [Reproducibility checklist](#reproducibility-checklist)
4. [Prerequisites](#prerequisites)
5. [Setting up the networks](#setting-up-the-networks)
6. [Environment variables](#environment-variables)
7. [Running the test suites](#running-the-test-suites)
8. [Reproducing the published benchmarks](#reproducing-the-published-benchmarks)
9. [Measurement scope](#measurement-scope)
10. [Security note: demo web UI and key custody](#security-note-demo-web-ui-and-key-custody)
11. [File layout](#file-layout)
12. [Troubleshooting](#troubleshooting)
13. [Citation](#citation)
14. [License](#license)
15. [Contact](#contact)

---

## What this is

PQ-Chain combines the following mechanisms for cross-jurisdictional digital forensic evidence transfer:

| Mechanism | Purpose |
|---|---|
| **ML-DSA multi-signature** (FIPS 204; ML-DSA-44/65/87, ECC baseline) | Per-signer-attributable post-quantum authorisation by a (t, n) committee; each member signs h‖ID_i |
| **Canonical signature bundle, stored off-chain** | Binary bundle encoding; only `bundleHash = SHA-256(bundle)` goes on-chain; the bundle is stored on IPFS replicas and in an archive before the 2PC starts |
| **2PC coordinator with on-chain state machines** | Transfer between Hyperledger Fabric (police side) and Hyperledger Besu (court side); atomic under an honest coordinator, inconsistencies of a Byzantine coordinator are detectable |
| **Encrypt-before-upload** | Evidence files are encrypted with AES-256-GCM; the file key is wrapped for PoliceOrg and CourtOrg with ML-KEM-768 (FIPS 203) |
| **Application-layer Shamir secret sharing** | Committee administration; each share is sealed to its member's ML-KEM-768 key |

Headline result (revised paper, Section 8.5): at (t, n) = (3, 5), signing, combining and verification account for 0.18–0.99 % of end-to-end latency (0.79 % for ML-DSA-65), and all cryptography including file encryption for 0.53–1.33 %. End-to-end latency (about 4.3 s) is dominated by Fabric's 2 s block-cutting timeout.

## What's in this repository

| Component | Path | Purpose |
|---|---|---|
| Multi-signature | `UI/utils/thresholdMultiSignature.js` | Algorithms 5 and 6: per-signer signing, aggregation, canonical encoding, verification against registered keys |
| Bundle store | `UI/utils/bundleStore.js` | Stores the bundle on the configured IPFS nodes (CID derived from `bundleHash`) and in a local archive |
| Bundle auditor | `UI/utils/bundleAuditor.js`, `UI/test-scripts/audit-bundle.js` | Fabric/Besu agreement, fetch by hash, hash check, signer set, bundle verification |
| Evidence encryption | `UI/utils/evidenceEncryption.js`, `UI/utils/pqSeal.js` | AES-256-GCM + ML-KEM-768 key wrapping; IPFS store of ciphertext and key envelope |
| Besu 2PC contract | `UI/EvidenceReceiverV2.sol` | Court-side `prepare` / `commit` / `abort` state machine |
| Besu transfer client | `UI/utils/besuTransferClient.js` | Coordinator-side wrapper around the contract |
| Fabric 2PC chaincode | `Chaincode/evidence/contracts/evidence-transfer.go` | Police-side `PrepareTransfer` / `CommitTransfer` / `AbortTransfer` |
| Fabric transfer client | `UI/utils/fabricTransferClient.js` | `FABRIC_MODE=real` (live network, used for all results); `stub` / `off` are test fixtures only |
| 2PC coordinator | `UI/utils/completeCrossChainMesher.js` | Algorithm 7: store, parallel prepare, commit/abort, timeout grace, recovery |
| Committee administration | `UI/utils/committeeManager.js` | Shamir shares sealed to members' ML-KEM-768 keys |
| Contract deployer | `UI/deploy-v2-contract.js` | Compiles and deploys `EvidenceReceiverV2.sol` |
| Fabric network | `Network/` | Minifab spec and scripts (Fabric 2.4.8), chaincode-as-a-service deployment |

## Reproducibility checklist

Table and figure numbers refer to the revised paper.

| Paper result | Table / Figure | Script | Raw output (`UI/test-scripts/test-results/revision/`) |
|---|---|---|---|
| Single-signer KeyGen / Sign / Verify, 1,000 iterations | Table 7, Fig. 2 | `UI/benchmark-crypto-1000.js` | `table9-crypto-1000-1790614484262.txt` |
| Multi-signature at (3, 5), in-pipeline | Table 8 | `UI/benchmark-multisig-2pc-e2e.js` | `benchmark-multisig-2pc-1790620322690.json` |
| End-to-end transfer on live Fabric + Besu, 80/80 Committed | Table 9, Fig. 3 | `UI/benchmark-multisig-2pc-e2e.js` | same file; console log `table10-11-e2e-console-1790619760000.txt` |
| Key, signature and bundle sizes | Table 10, Fig. 4 | `UI/test-scripts/measure-bundle-size.js` | `bundle-scaling-1790614552089.json` (t = 3 rows) |
| Bundle size and latency vs. threshold t (t = 1…21) | Table 11, Fig. 5 | `UI/test-scripts/measure-bundle-size.js` | `bundle-scaling-1790614552089.json` |
| Encryption cost, 1 MB – 1 GB | Table 12 | `UI/test-scripts/measure-encryption.js` | `encryption-1790619494909.json` |
| 32/32 multi-signature tests (8 scenarios × 4 algorithms) | Section 8.1 | `UI/test-scripts/test-multi-sig-real.js` | `multisig-tests-1790620673000.txt` |
| 9/9 Besu contract tests | Section 8.1 | `UI/test-scripts/test-besu-v2.js` | `besu-v2-tests-1790620673000.txt` |
| 19/19 Fabric state-machine checks on the live network | Section 8.1 | `UI/test-scripts/test-fabric-fsm.js` | `fabric-fsm-1790617613000.txt` |
| 5 coordinator scenarios on both live chains (11/11 checks) | Section 8.1 | `UI/test-scripts/test-2pc-mesher.js` | `coordinator-real-1790617613000.txt` |

Only the runs used in the paper are listed above; earlier, superseded runs are not used in the paper. Some script comments and raw-file names use the table numbers of the submitted version (Tables 9–11 there are Tables 7–9 in the revised paper).

## Prerequisites

| Software | Version used for the paper |
|---|---|
| Node.js | 24.21.0 (18+ should work) |
| Docker Engine | 29.1.3 |
| Hyperledger Besu | 24.12.2 (`hyperledger/besu:24.12.2`), `--network=dev` |
| Hyperledger Fabric | 2.4.8 via Minifab (`hyperledgerlabs/minifab`) |
| IPFS Kubo | 0.32.1 (`ipfs/kubo:v0.32.1`), three private nodes |
| Go | only needed to build the chaincode outside Docker |

Hardware of the reported runs: Intel Core i7-1360P (12 cores / 16 threads), 16 GB RAM, Ubuntu 26.04 LTS, all nodes on one host, AC power, performance profile.

## Setting up the networks

### 1. Clone and install

```bash
git clone https://github.com/arifanoushad/pq-chain.git
cd pq-chain
(cd Client && npm ci)   # Fabric SDK client, used by the committee manager
cd UI && npm ci
```

### 2. Besu (court side)

```bash
docker run -d --name pqchain-besu -p 127.0.0.1:8545:8545 hyperledger/besu:24.12.2 \
  --network=dev --miner-enabled \
  --miner-coinbase=0xfe3b557e8fb62b89f4916b721be55ceb828dbd73 \
  --rpc-http-enabled --rpc-http-host=0.0.0.0 --rpc-http-port=8545 \
  --rpc-http-api=ETH,NET,WEB3,ADMIN --host-allowlist="*" --rpc-http-cors-origins="*"
```

(`besu-network/docker-compose.yml` starts an equivalent node with the same image.)

**Besu key.** The scripts read the coordinator's (deployer's) private key from `COORDINATOR_KEY`; no key is stored in this repository. For a `--network=dev` node, use the private key of the prefunded dev account `0xfe3b557e8fb62b89f4916b721be55ceb828dbd73`, published in the Besu documentation ([Accounts for testing](https://docs.besu-eth.org/private-networks/reference/accounts-for-testing)). These test accounts must never be used on a public network.

```bash
export COORDINATOR_KEY=0x...   # dev account private key from the Besu documentation
node deploy-v2-contract.js     # writes UI/artifacts-v2/EvidenceReceiverV2.json
export V2_CONTRACT_ADDRESS=$(node -e "console.log(require('./artifacts-v2/EvidenceReceiverV2.json').address)")
```

### 3. IPFS (three private Kubo replicas)

```bash
for i in 1 2 3; do
  docker run -d --name pqchain-kubo$i \
    -p 127.0.0.1:$((5000+i)):5001 -p 127.0.0.1:$((4000+i)):4001 -p 127.0.0.1:$((8079+i)):8080 \
    ipfs/kubo:v0.32.1
done
# make the nodes private (no public bootstrap, no public routing), then restart them
for i in 1 2 3; do
  docker exec pqchain-kubo$i ipfs bootstrap rm --all
  docker exec pqchain-kubo$i ipfs config Routing.Type none
  docker restart pqchain-kubo$i
done
export BUNDLE_IPFS_URLS=http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003
export BUNDLE_MIN_REPLICAS=3
```

### 4. Fabric (police side)

The Fabric network (PoliceOrg and CourtOrg with one peer and CouchDB each, three Raft orderers, channel `evidencechannel`) is created with Minifab from `Network/spec.yaml`. Minifab has been archived by Hyperledger Labs since November 2023; `Network/minifab-docker29.sh` makes it work with Docker Engine ≥ 29 without changing the host Docker daemon.

```bash
cd Network
./startNetwork.sh              # Minifab network, Fabric 2.4.8
./deploy-evidence-ccaas.sh     # evidence chaincode as an external service (ccaas_builder)
cd ../UI
export FABRIC_MODE=real
```

With recent Docker Engine releases the Fabric 2.4.8 peer's built-in chaincode image build fails, so the chaincode runs as a chaincode service built with the same `fabric-ccenv:2.4.8` toolchain (`Chaincode/evidence/Dockerfile`).

### 5. Evidence recipients (ML-KEM-768 keys)

```bash
node scripts/generate-recipient-keys.js   # public keys → UI/config/, secret keys → UI/data/keys/ (not committed)
```

### 6. Test files

The benchmarks and tests that read evidence files from `UI/test-scripts/test-files/` need them generated once (10 KB – 10 MB of random data; not shipped):

```bash
node test-scripts/create-test-files.js
```

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `COORDINATOR_KEY` | deployer, Besu client, Besu tests | Coordinator's Besu private key (hex), **required** |
| `V2_CONTRACT_ADDRESS` | Besu client, Besu tests | Deployed `EvidenceReceiverV2` address |
| `BESU_RPC` | Besu scripts | JSON-RPC URL (default `http://localhost:8545`) |
| `FABRIC_MODE` | Fabric client | `real` for all reported results; `stub` / `off` for offline tests |
| `FABRIC_CCP`, `FABRIC_WALLET`, `FABRIC_CHANNEL`, `FABRIC_CHAINCODE`, `FABRIC_IDENTITY` | Fabric client | Override the Minifab defaults (`Network/vars/profiles/…`, `evidencechannel`, `evidence`, `Admin`) |
| `BUNDLE_IPFS_URLS`, `BUNDLE_MIN_REPLICAS`, `BUNDLE_ARCHIVE_DIR` | bundle store, encryption | IPFS API URLs, required number of replicas, local bundle archive |
| `BENCH_ITER`, `BENCH_T`, `BENCH_N`, `BENCH_ALGOS`, `BENCH_FILE_MB` | e2e benchmark | Defaults: 20, 3, 5, all four algorithms, 10 MB |

## Running the test suites

Run from `UI/` with the environment of the previous sections.

```bash
node test-scripts/test-multi-sig-real.js   # 32/32 (8 scenarios × 4 algorithms); no network needed
node test-scripts/test-besu-v2.js          # 9/9; needs Besu
node test-scripts/test-fabric-fsm.js       # 19/19; needs Fabric (FABRIC_MODE=real)
node test-scripts/test-2pc-mesher.js       # 5 scenarios, 11/11 checks on both chains
node test-scripts/test-bundle-store.js     # bundle storage and auditing
node test-scripts/test-evidence-encryption.js
node test-scripts/test-shamir-custody.js
```

## Reproducing the published benchmarks

Run `node test-scripts/create-test-files.js` first (see [Test files](#6-test-files)).

```bash
node benchmark-crypto-1000.js                 # Table 7
node benchmark-multisig-2pc-e2e.js            # Tables 8 and 9 (80 transfers, 10 MB evidence each)
node test-scripts/measure-bundle-size.js      # Tables 10 and 11
node test-scripts/measure-encryption.js       # Table 12
```

Each iteration of the end-to-end benchmark encrypts and uploads a 10 MB evidence file, collects t = 3 partial signatures, stores the bundle on the IPFS replicas, runs the 2PC on both chains and verifies the bundle on the court side. Two warm-up iterations per algorithm are discarded. Expected means for ML-DSA-65 on the paper's hardware: Sign (t = 3) 28.3 ms, Store 12.8 ms, Prepare 2,046 ms, Finalize 2,041 ms, Verify 5.8 ms, end-to-end 4,314 ms. Prepare and Finalize are dominated by Fabric's BatchTimeout of 2 s, so absolute latencies depend mainly on the orderer configuration, not on the CPU.

## Measurement scope

- All layers (ML-DSA signing and verification, Fabric chaincode, Besu contract, coordinator, IPFS) run against real code on real networks; no Fabric stub is used in any reported timing.
- All nodes run on one host; Besu is a single development node (`--network=dev`, about one block per second), not a multi-validator QBFT network.
- The stub mode of `fabricTransferClient.js` is retained only as a labelled test fixture for offline tests.

## Security note: demo web UI and key custody

No users, keys or committees ship with this repository. `UI/data/` is created on first run (`UI/data/users.json` starts empty), and users are created by registering through the web UI (`npm start`, then the registration page).

The Express web UI in `UI/` is a demonstration front end. **For convenience only, it keeps each registered user's private signing key on the server** (`UI/data/users.json`) and logs users in with that key. This is **not** the trust model of PQ-Chain: the protocol assumes that each committee member holds their own ML-DSA signing key (on their own device or in an HSM) and that no server can sign on their behalf. `UI/data/users.json` and all other key material (`UI/data/keys/`, `UI/data/shares/`, Fabric wallets and crypto material under `Network/vars/`) are git-ignored and must never be committed. A deployment should replace the demo login with challenge-response login using member-held keys.

The benchmarks and test suites do not use the web UI or its stored keys: they generate keys in memory for each run.

## File layout

```
pq-chain/
├── Chaincode/evidence/          # Fabric chaincode (Go) + Dockerfile for chaincode-as-a-service
├── Client/, Event/              # Fabric SDK client and event listener (optional)
├── Network/                     # Minifab spec, start and chaincode deployment scripts
├── besu-network/                # docker-compose for the Besu dev node
└── UI/
    ├── EvidenceReceiverV2.sol   # Besu 2PC contract
    ├── deploy-v2-contract.js
    ├── benchmark-crypto-1000.js
    ├── benchmark-multisig-2pc-e2e.js
    ├── scripts/                 # ML-KEM recipient key generation
    ├── utils/                   # protocol implementation
    ├── test-scripts/            # test suites, measurement scripts, raw results (test-results/revision/)
    ├── routes/, views/, public/, app.js   # demo web UI (optional)
    └── package.json
```

## Troubleshooting

- **`COORDINATOR_KEY env var is required`**: export the key as described under [Besu key](#2-besu-court-side).
- **Deployer has zero balance**: `COORDINATOR_KEY` is not the key of a prefunded account on this node.
- **`FabricTransferClient: set FABRIC_MODE`**: the mode must be chosen explicitly (`real` for the paper's results).
- **`FABRIC_MODE=real: connection profile … or wallet … not found`**: the Minifab network has not been created, or `FABRIC_CCP` / `FABRIC_WALLET` point elsewhere. Minifab advertises endpoints on the host's LAN IP; if that IP changes, restart the network.
- **Bundle store fails with fewer than `BUNDLE_MIN_REPLICAS` replicas**: check that all IPFS nodes in `BUNDLE_IPFS_URLS` are running.

## Citation

Citation will be added once the paper is published. In the meantime, please cite this repository directly:

```bibtex
@misc{pqchain2026repo,
  author       = {Arifa P and Jithesh K and Syamkrishnan M.S.},
  title        = {{PQ-Chain}: Reference implementation of a Post-Quantum Attributable Signature-Bundle Protocol with Two-Phase Commit for Cross-Chain Digital Forensic Evidence Transfer},
  year         = {2026},
  howpublished = {\url{https://github.com/arifanoushad/pq-chain}},
  note         = {Manuscript under review at Journal of Information Security and Applications (Elsevier)}
}
```

## License

This implementation is released under the **MIT License** (see `LICENSE` file).

> The paper text and figures are *not* covered by this licence; they are subject to the journal's submission and copyright agreements.

## Acknowledgments

- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) for ML-DSA (FIPS 204) and ML-KEM (FIPS 203)
- [Hyperledger Besu](https://besu.hyperledger.org/) and [Hyperledger Fabric](https://www.hyperledger.org/projects/fabric)
- [Minifab](https://github.com/hyperledger-labs/minifabric) for the Fabric network tooling
- [Web3.js](https://web3js.readthedocs.io/) and [IPFS / Kubo](https://docs.ipfs.tech/)

## Contact

**Arifa P** (corresponding author)
Department of Computer Science
Mary Matha Arts and Science College, Mananthavady, Kerala, India
Research Scholar, Kannur University
Email: rs_arifap@kannuruniv.ac.in
ORCID: 0009-0000-4477-0451
GitHub: [@arifanoushad](https://github.com/arifanoushad)

## Version history

| Version | Date | Changes |
|---|---|---|
| jisa-r1 | Oct 2026 | Major revision: live Fabric 2.4.8 + Besu for all results; bundle stored off-chain (hash on-chain, canonical encoding); encrypt-before-upload (AES-256-GCM + ML-KEM-768); coordinator timeout grace and recovery; signed message h‖ID_i; key binding to registered keys; Shamir shares sealed to ML-KEM keys; Besu key moved to an environment variable |
| v3.0 | May 2026 | Real ML-DSA multi-signature, V2 Solidity contract, 2PC coordinator with live Besu (version submitted to JISA) |
| v2.0 | April 2026 | First real Dilithium implementation |
| v1.1 | March 2026 | userManager refactor |
| v1.0 | (initial) | Lattice-based threshold ring signcryption prototype |
