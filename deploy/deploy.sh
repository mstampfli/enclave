#!/usr/bin/env bash
# Deploy the enclave relay to cp1 from a dev device.
#
# The server authenticates to nothing: this builds the image HERE, ships it over
# SSH, and starts it there. cp1 needs no GitHub credential and no Rust
# toolchain. Idempotent -- rerun it to upgrade.
#
#   ./deploy/deploy.sh              # build, ship, start, smoke-test
#   HOST=cp1 ./deploy/deploy.sh     # same, explicit host
set -euo pipefail

HOST="${HOST:-cp1}"
# cp1's tailnet address: both ports publish here, never 0.0.0.0, so the host
# firewall and the headscale ACL stay in force.
TAILNET_IP="${TAILNET_IP:-100.64.0.3}"
REMOTE_DIR="${REMOTE_DIR:-/srv/docker/enclave}"
IMAGE="enclave-server:local"
# Must match the USER uid in deploy/Dockerfile: the relay runs non-root and
# refuses to start if it cannot write its state directory.
DATA_UID=10001

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

echo "==> building $IMAGE"
docker build -f deploy/Dockerfile -t "$IMAGE" .

echo "==> checking $HOST is reachable"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" true

echo "==> shipping the image to $HOST"
docker save "$IMAGE" | ssh "$HOST" 'sudo docker load'

echo "==> installing the compose file"
ssh "$HOST" "sudo install -d -m 0755 '$REMOTE_DIR'"
scp -q deploy/docker-compose.yml "$HOST:/tmp/enclave-compose.yml"
ssh "$HOST" "sudo install -m 0644 /tmp/enclave-compose.yml '$REMOTE_DIR/docker-compose.yml' && rm -f /tmp/enclave-compose.yml"

# The state directory must be owned by the container's uid. Without this the
# relay cannot persist, and it now refuses to start rather than silently losing
# every account on the next restart.
echo "==> ensuring the state directory is owned by $DATA_UID"
ssh "$HOST" "sudo install -d -o $DATA_UID -g $DATA_UID -m 0700 '$REMOTE_DIR/data'"

echo "==> starting the relay"
ssh "$HOST" "cd '$REMOTE_DIR' && sudo docker compose up -d"
sleep 3
ssh "$HOST" "cd '$REMOTE_DIR' && sudo docker compose ps && sudo docker compose logs --tail 5"

echo "==> verifying the published ports are tailnet-only"
ssh "$HOST" "sudo ss -tlnp | grep ':8443' || true; sudo ss -ulnp | grep ':8444' || true"

cat <<EOF

Relay is up on $TAILNET_IP:8443 (signaling) and $TAILNET_IP:8444/udp (media).

Smoke-test it end to end from this device:

  ENCLAVE_RELAY_URL=ws://$TAILNET_IP:8443 \\
    cargo test -p enclave-client --test deployed_relay -- --nocapture

Hub-side exposure (TLS + the VPN gate) is a separate, one-time step -- see
deploy/README.md.
EOF
