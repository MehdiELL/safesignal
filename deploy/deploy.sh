#!/usr/bin/env bash
# Deploy SafeSignal to GenLayer Testnet Bradbury (chain 4221).
#   npm install -g genlayer
#   genlayer account import --name deployer --private-key 0x<key>
#   bash deploy/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
genlayer network set testnet-bradbury
genlayer deploy --contract contracts/safesignal.py
