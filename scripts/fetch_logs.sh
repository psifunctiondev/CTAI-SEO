#!/bin/bash
# Fetch latest access logs from CTAI hosting via SFTP
# Usage: ./scripts/fetch_logs.sh
#
# Requires: expect (built into macOS)
# Reads credentials from: ../.secrets/ctai-sftp.txt (in workspace root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/access_logs"
SECRETS_FILE="$HOME/.openclaw/workspace/.secrets/ctai-sftp.txt"

# Parse credentials
HOST=$(grep '^Host:' "$SECRETS_FILE" | awk '{print $2}')
PORT=$(grep '^Port:' "$SECRETS_FILE" | awk '{print $2}')
USER=$(grep '^User:' "$SECRETS_FILE" | awk '{print $2}')
PASS=$(grep '^Password:' "$SECRETS_FILE" | cut -d' ' -f2-)

if [ -z "$HOST" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "ERROR: Could not read credentials from $SECRETS_FILE"
    exit 1
fi

echo "Fetching logs from $HOST..."
echo "  Local dir: $LOG_DIR"

mkdir -p "$LOG_DIR"

# Use expect to handle SFTP password auth
expect -c "
spawn sftp -o StrictHostKeyChecking=no -P $PORT ${USER}@${HOST}
expect {
    \"password:\" { send \"${PASS}\r\" }
    \"Password:\" { send \"${PASS}\r\" }
}
expect \"sftp>\"
send \"lcd $LOG_DIR\r\"
expect \"sftp>\"
send \"cd logs\r\"
expect \"sftp>\"
send \"mget access.log.*\r\"
expect \"sftp>\"
send \"bye\r\"
expect eof
"

# Remove access.log.current (symlink/duplicate of latest)
rm -f "$LOG_DIR/access.log.current"

echo ""
echo "Done. Files in $LOG_DIR:"
ls -lh "$LOG_DIR"/access.log.* | wc -l
echo "log files downloaded."
