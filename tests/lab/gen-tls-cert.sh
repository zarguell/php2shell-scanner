#!/bin/bash
# Generate a throwaway self-signed cert for the TLS lab service.
# Usage: ./tests/lab/gen-tls-cert.sh   (writes tests/lab/tls-cert/)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tls-cert"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -days 7 \
  -subj "/CN=php2shell-lab" 2>/dev/null
echo "wrote $DIR/cert.pem + key.pem"
