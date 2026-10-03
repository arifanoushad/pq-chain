#!/bin/bash
# Deploy the evidence chaincode as a service (Fabric ccaas_builder) on the
# Minifab network created by startNetwork.sh (Fabric 2.4.8).
#
# Why CCaaS: on Docker Engine >= 29 the Fabric 2.4.8 peer compiles the
# chaincode in fabric-ccenv:2.4.8 successfully but its built-in Docker client
# cannot build the chaincode image ("docker image build failed: write: broken
# pipe"). The image is therefore built with the host Docker client from the
# same fabric-ccenv:2.4.8 toolchain (Chaincode/evidence/Dockerfile) and the
# peers connect to it.
#
# Usage (from this directory, after startNetwork.sh):  ./deploy-evidence-ccaas.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/minifab-docker29.sh"
CC_NAME=evidence CC_VERSION=1.0 CC_LABEL=evidence_1.0 CC_HOST=evidence-cc
CLI=$(docker ps --format '{{.Names}}' | grep '_cli$' | head -1)
NET=$(docker inspect "$CLI" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')

docker build -q -t pqchain/evidence-cc:$CC_VERSION "$HERE/../Chaincode/evidence"

# CCaaS package, built on the host with GNU tar as deterministic archives so
# the package ID is stable across re-runs
PKG_DIR=$(mktemp -d)
TAR="tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf -"
echo "{\"address\":\"$CC_HOST:9999\",\"dial_timeout\":\"10s\",\"tls_required\":false}" > "$PKG_DIR/connection.json"
echo "{\"type\":\"ccaas\",\"label\":\"$CC_LABEL\"}" > "$PKG_DIR/metadata.json"
(cd "$PKG_DIR" && $TAR connection.json | gzip -n > code.tar.gz && $TAR metadata.json code.tar.gz | gzip -n > pkg.tar.gz)
docker exec "$CLI" mkdir -p /vars/chaincode/$CC_NAME
docker cp "$PKG_DIR/pkg.tar.gz" "$CLI:/vars/chaincode/$CC_NAME/${CC_NAME}_ccaas_$CC_VERSION.tar.gz"
rm -rf "$PKG_DIR"

docker exec -i "$CLI" bash -s <<SCRIPT
set -e
cd /vars/chaincode/$CC_NAME
export CORE_PEER_TLS_ENABLED=true
for ORG in PoliceOrg CourtOrg; do
  export CORE_PEER_ADDRESS=peer1.\$ORG.evidence.com:7051 CORE_PEER_LOCALMSPID=\$ORG-evidence-com
  export CORE_PEER_TLS_ROOTCERT_FILE=/vars/keyfiles/peerOrganizations/\$ORG.evidence.com/peers/peer1.\$ORG.evidence.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=/vars/keyfiles/peerOrganizations/\$ORG.evidence.com/users/Admin@\$ORG.evidence.com/msp
  peer lifecycle chaincode install ${CC_NAME}_ccaas_$CC_VERSION.tar.gz \\
    || peer lifecycle chaincode queryinstalled | grep -q "\$(peer lifecycle chaincode calculatepackageid ${CC_NAME}_ccaas_$CC_VERSION.tar.gz)"   # already installed
done
peer lifecycle chaincode calculatepackageid ${CC_NAME}_ccaas_$CC_VERSION.tar.gz > package_id
SCRIPT
PKID=$(docker exec "$CLI" cat /vars/chaincode/$CC_NAME/package_id)
echo "package id: $PKID"

docker rm -f "$CC_HOST" >/dev/null 2>&1 || true
docker run -d --name "$CC_HOST" --network "$NET" --restart unless-stopped \
  -e CHAINCODE_ID="$PKID" -e CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999 pqchain/evidence-cc:$CC_VERSION

# Approve (both orgs) and commit with the exact package ID; minifab's approve
# selects packages by label only, which is ambiguous after re-deployments.
docker exec -i "$CLI" bash -s <<SCRIPT
set -e
ORDERER=orderer1.evidence.com:7050
ORDERER_CA=/vars/keyfiles/ordererOrganizations/evidence.com/orderers/orderer1.evidence.com/tls/ca.crt
peer_env() {
  export CORE_PEER_TLS_ENABLED=true CORE_PEER_ADDRESS=peer1.\$1.evidence.com:7051 CORE_PEER_LOCALMSPID=\$1-evidence-com
  export CORE_PEER_TLS_ROOTCERT_FILE=/vars/keyfiles/peerOrganizations/\$1.evidence.com/peers/peer1.\$1.evidence.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=/vars/keyfiles/peerOrganizations/\$1.evidence.com/users/Admin@\$1.evidence.com/msp
}
peer_env PoliceOrg
SEQ=\$(peer lifecycle chaincode querycommitted -C evidencechannel -O json 2>/dev/null \\
      | jq -r '.chaincode_definitions[]? | select(.name=="$CC_NAME") | .sequence' || true)
SEQ=\$(( \${SEQ:-0} + 1 ))
for ORG in PoliceOrg CourtOrg; do
  peer_env \$ORG
  peer lifecycle chaincode approveformyorg -C evidencechannel -n $CC_NAME -v $CC_VERSION \\
    --package-id $PKID --sequence \$SEQ -o \$ORDERER --tls --cafile \$ORDERER_CA
done
peer lifecycle chaincode commit -C evidencechannel -n $CC_NAME -v $CC_VERSION --sequence \$SEQ \\
  -o \$ORDERER --tls --cafile \$ORDERER_CA \\
  --peerAddresses peer1.PoliceOrg.evidence.com:7051 \\
  --tlsRootCertFiles /vars/keyfiles/peerOrganizations/PoliceOrg.evidence.com/peers/peer1.PoliceOrg.evidence.com/tls/ca.crt \\
  --peerAddresses peer1.CourtOrg.evidence.com:7051 \\
  --tlsRootCertFiles /vars/keyfiles/peerOrganizations/CourtOrg.evidence.com/peers/peer1.CourtOrg.evidence.com/tls/ca.crt
peer lifecycle chaincode querycommitted -C evidencechannel -n $CC_NAME
SCRIPT
