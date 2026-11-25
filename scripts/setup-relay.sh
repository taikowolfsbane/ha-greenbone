#!/bin/sh
# Sets up a systemd-managed socat relay that bridges gvmd's internal GMP unix
# socket (used by the official Greenbone Community Edition Docker Compose
# deployment) to a plain TCP port, restricted to one source IP - typically
# your Home Assistant server. See the main README for why this is needed.
#
# Usage: sudo ./setup-relay.sh <home-assistant-ip> [port]
#
# Must be run on the Greenbone host itself (not Home Assistant), as a user
# that can run docker and systemctl (root, or a user with the right sudo/group
# access).

set -e

HA_IP="$1"
PORT="${2:-9391}"

if [ -z "$HA_IP" ]; then
    echo "Usage: sudo $0 <home-assistant-ip> [port]" >&2
    exit 1
fi

if ! command -v socat >/dev/null 2>&1; then
    echo "Installing socat..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y socat
    else
        echo "socat is not installed and this script only knows how to install it" \
             "via apt-get. Install socat manually, then re-run this script." >&2
        exit 1
    fi
fi

VOLUME_NAME=$(docker volume ls --format '{{.Name}}' | grep 'gvmd_socket_vol$' | head -n1)
if [ -z "$VOLUME_NAME" ]; then
    echo "Could not find a Docker volume ending in 'gvmd_socket_vol'." >&2
    echo "Is the official Greenbone Community Edition Docker Compose stack running here?" >&2
    exit 1
fi

MOUNTPOINT=$(docker volume inspect "$VOLUME_NAME" --format '{{.Mountpoint}}')
SOCKET_PATH="$MOUNTPOINT/gvmd.sock"

if [ ! -S "$SOCKET_PATH" ]; then
    echo "Found volume '$VOLUME_NAME' but no socket at $SOCKET_PATH" >&2
    echo "Is the gvmd container currently running?" >&2
    exit 1
fi

echo "Found gvmd socket: $SOCKET_PATH"

cat > /etc/systemd/system/gvmd-gmp-relay.service << EOF
[Unit]
Description=TCP relay from gvmd GMP unix socket to Home Assistant (restricted source IP)
Requires=docker.service
After=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${PORT},fork,reuseaddr,range=${HA_IP}/32 UNIX-CONNECT:${SOCKET_PATH}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now gvmd-gmp-relay.service

echo
echo "Relay installed and running: TCP port ${PORT}, restricted to ${HA_IP}."
echo "In Home Assistant, add the Greenbone Vulnerabilities integration pointing at:"
echo "  Host: $(hostname -I 2>/dev/null | awk '{print $1}')"
echo "  Port: ${PORT}"
