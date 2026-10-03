#!/bin/bash

# JISA revision: Docker Engine >= 29 and paths with spaces need a shim for the
# (archived) Minifab; see minifab-docker29.sh. The chaincode is deployed
# afterwards with ./deploy-evidence-ccaas.sh.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/minifab-docker29.sh"
cd "$FABNET_LINK"

echo "Bootstrapping ......."
minifab netup -s couchdb -e true -i 2.4.8 -o PoliceOrg.evidence.com 

sleep 5

echo "Creating channel"
minifab create -c evidencechannel  # This creates the channel

sleep 2

echo "Joining channel"
minifab join -c evidencechannel  # Peers from both organizations join the channel

sleep 2

echo "Anchor Update"
minifab anchorupdate  # Update anchor peers for both organizations
sleep 2

echo "#### Network Setup Complete ###"
echo "Generating Required Materials"
minifab profilegen -c evidencechannel  # Generate necessary channel configurations and materials

