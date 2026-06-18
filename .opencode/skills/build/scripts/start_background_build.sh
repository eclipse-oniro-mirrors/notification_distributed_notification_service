#!/bin/bash
# Start a background build process for OpenHarmony
# Usage: start_background_build.sh <build_command> <oh_root> [log_file]
#
# This script launches a build in the background using nohup,
# redirects output to a log file, and records the PID for monitoring.

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <build_command> <oh_root> [log_file]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  build_command  Full build command (e.g., './build.sh --product-name rk3568 --ccache')" >&2
    echo "  oh_root        OpenHarmony root directory" >&2
    echo "  log_file       Optional log file path (default: <oh_root>/out/build_background.log)" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 './build.sh --product-name rk3568 --build-target distributed_notification_service --ccache' /path/to/OpenHarmony" >&2
}

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

BUILD_COMMAND="$1"
OH_ROOT="$2"
LOG_FILE="${3:-$OH_ROOT/out/build_background.log}"
PID_FILE="$OH_ROOT/.build.pid"

if [[ ! -d "$OH_ROOT" ]]; then
    echo -e "${RED}Error: OpenHarmony root not found: $OH_ROOT${NC}" >&2
    exit 1
fi

if [[ ! -f "$OH_ROOT/build.sh" ]]; then
    echo -e "${RED}Error: build.sh not found in $OH_ROOT${NC}" >&2
    exit 1
fi

mkdir -p "$(dirname "$LOG_FILE")"

if [[ -f "$LOG_FILE" ]]; then
    echo -e "${YELLOW}Clearing old log file: $LOG_FILE${NC}"
    > "$LOG_FILE"
fi

if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo -e "${YELLOW}Warning: Previous build process (PID $OLD_PID) is still running${NC}"
        echo -e "${YELLOW}Killing old process...${NC}"
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$OLD_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
fi

START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
START_EPOCH=$(date +%s)

echo -e "${GREEN}Starting background build...${NC}"
echo "Command: $BUILD_COMMAND"
echo "Working directory: $OH_ROOT"
echo "Log file: $LOG_FILE"
echo "Start time: $START_TIME"
echo ""

cd "$OH_ROOT"

nohup bash -c "$BUILD_COMMAND" > "$LOG_FILE" 2>&1 &
BUILD_PID=$!

echo "$BUILD_PID" > "$PID_FILE"

sleep 1

if ! kill -0 "$BUILD_PID" 2>/dev/null; then
    echo -e "${RED}Error: Build process failed to start or exited immediately${NC}"
    echo "Check log file for details: $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi

echo -e "${GREEN}Background build started successfully${NC}"
echo ""
echo "PID: $BUILD_PID"
echo "PID file: $PID_FILE"
echo "Log file: $LOG_FILE"
echo "Start time: $START_TIME"
echo "Start epoch: $START_EPOCH"
echo ""
echo "Monitor progress with:"
echo "  bash <skill-dir>/scripts/poll_build.sh <product> $OH_ROOT"
echo ""
echo "Or manually:"
echo "  tail -f $LOG_FILE"
echo "  kill $BUILD_PID  # to cancel"
