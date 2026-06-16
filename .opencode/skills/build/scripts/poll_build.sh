#!/bin/bash
# Poll OpenHarmony build progress with adaptive delay
# Usage: poll_build.sh <product> <oh_root> [max_wait_seconds]
#
# This script monitors a background build process by polling the build log.
# It uses progress-aware adaptive delay: as build progresses, polling becomes more frequent.
#
# Delay algorithm:
#   progress = current / total (from ninja output [current/total])
#   delay = max_delay - (max_delay - min_delay) * progress
#   min_delay = 10s, max_delay = 300s (5min)
#
# Exit codes:
#   0 - Build successful
#   1 - Build failed
#   2 - Build timeout
#   3 - Build process not found

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

MIN_DELAY=10
MAX_DELAY=300
DEFAULT_MAX_WAIT=7200

usage() {
    echo "Usage: $0 <product> <oh_root> [max_wait_seconds]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  product            Product name (e.g., rk3568, standard)" >&2
    echo "  oh_root            OpenHarmony root directory" >&2
    echo "  max_wait_seconds   Maximum wait time in seconds (default: $DEFAULT_MAX_WAIT)" >&2
    echo "" >&2
    echo "Exit codes:" >&2
    echo "  0 - Build successful" >&2
    echo "  1 - Build failed" >&2
    echo "  2 - Build timeout" >&2
    echo "  3 - Build process not found" >&2
}

build_log_path() {
    local product="$1"
    local root="$2"
    if [[ "$product" == "host_product" ]]; then
        echo "$root/out/host/host_product/build.log"
    elif [[ "$product" == "ohos-sdk" || "$product" == "sdk" ]]; then
        echo "$root/out/sdk/build.log"
    elif [[ "$product" == "standard" || "$product" == "independent" ]]; then
        echo "$root/out/standard/build.log"
    else
        echo "$root/out/$product/build.log"
    fi
}

get_ninja_progress() {
    local log_file="$1"
    if [[ ! -f "$log_file" ]]; then
        echo "0 0"
        return
    fi
    local last_progress
    last_progress=$(grep -oE '\[[0-9]+/[0-9]+\]' "$log_file" 2>/dev/null | tail -1 || echo "")
    if [[ -z "$last_progress" ]]; then
        echo "0 0"
        return
    fi
    local current total
    current=$(echo "$last_progress" | grep -oE '[0-9]+' | head -1)
    total=$(echo "$last_progress" | grep -oE '[0-9]+' | tail -1)
    echo "${current:-0} ${total:-0}"
}

calculate_delay() {
    local progress="$1"
    local min_delay="$2"
    local max_delay="$3"
    local delay
    delay=$(awk "BEGIN {d = $max_delay - ($max_delay - $min_delay) * $progress; printf \"%.0f\", d}")
    if (( delay < min_delay )); then
        delay=$min_delay
    fi
    if (( delay > max_delay )); then
        delay=$max_delay
    fi
    echo "$delay"
}

format_duration() {
    local seconds="$1"
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    if (( hours > 0 )); then
        printf "%dh%dm%ds" "$hours" "$minutes" "$secs"
    elif (( minutes > 0 )); then
        printf "%dm%ds" "$minutes" "$secs"
    else
        printf "%ds" "$secs"
    fi
}

if [[ $# -lt 2 ]]; then
    usage
    exit 3
fi

PRODUCT="$1"
OH_ROOT="$2"
MAX_WAIT="${3:-$DEFAULT_MAX_WAIT}"

PID_FILE="$OH_ROOT/.build.pid"
LOG_FILE=$(build_log_path "$PRODUCT" "$OH_ROOT")
BG_LOG_FILE="$OH_ROOT/out/build_background.log"

if [[ ! -f "$PID_FILE" ]]; then
    echo -e "${RED}Error: PID file not found: $PID_FILE${NC}"
    echo "Is a background build running? Start one with start_background_build.sh"
    exit 3
fi

BUILD_PID=$(cat "$PID_FILE")

if ! kill -0 "$BUILD_PID" 2>/dev/null; then
    if [[ -f "$BG_LOG_FILE" ]]; then
        if grep -q "=====build successful=====" "$BG_LOG_FILE" 2>/dev/null; then
            echo -e "${GREEN}BUILD_SUCCESS${NC}"
            echo "Build completed successfully (process already exited)"
            rm -f "$PID_FILE"
            exit 0
        elif grep -q "FAILED:" "$BG_LOG_FILE" 2>/dev/null; then
            echo -e "${RED}BUILD_FAILED${NC}"
            echo "Build failed (process already exited)"
            rm -f "$PID_FILE"
            exit 1
        fi
    fi
    echo -e "${RED}Error: Build process (PID $BUILD_PID) is not running${NC}"
    rm -f "$PID_FILE"
    exit 3
fi

ACTIVE_LOG="$BG_LOG_FILE"
if [[ -f "$LOG_FILE" ]] && [[ ! -f "$BG_LOG_FILE" ]]; then
    ACTIVE_LOG="$LOG_FILE"
fi

START_EPOCH=$(date +%s)
POLL_COUNT=0
LAST_PROGRESS_LINE=""

echo -e "${BLUE}=== OpenHarmony Build Poller ===${NC}"
echo "Product: $PRODUCT"
echo "PID: $BUILD_PID"
echo "Log file: $ACTIVE_LOG"
echo "Max wait: $(format_duration $MAX_WAIT)"
echo "Delay range: ${MIN_DELAY}s - ${MAX_DELAY}s"
echo ""

while true; do
    CURRENT_EPOCH=$(date +%s)
    ELAPSED=$((CURRENT_EPOCH - START_EPOCH))

    if (( ELAPSED >= MAX_WAIT )); then
        echo ""
        echo -e "${RED}BUILD_TIMEOUT${NC}"
        echo "Elapsed: $(format_duration $ELAPSED)"
        echo "Max wait: $(format_duration $MAX_WAIT)"
        echo "Build process (PID $BUILD_PID) is still running"
        echo "Log file: $ACTIVE_LOG"
        exit 2
    fi

    if ! kill -0 "$BUILD_PID" 2>/dev/null; then
        wait "$BUILD_PID" 2>/dev/null || EXIT_CODE=$?
        EXIT_CODE=${EXIT_CODE:-0}

        if [[ $EXIT_CODE -eq 0 ]]; then
            echo ""
            echo -e "${GREEN}BUILD_SUCCESS${NC}"
            echo "Elapsed: $(format_duration $ELAPSED)"
            echo "Exit code: $EXIT_CODE"
            echo "Log file: $ACTIVE_LOG"
            rm -f "$PID_FILE"
            exit 0
        else
            echo ""
            echo -e "${RED}BUILD_FAILED${NC}"
            echo "Elapsed: $(format_duration $ELAPSED)"
            echo "Exit code: $EXIT_CODE"
            echo "Log file: $ACTIVE_LOG"
            rm -f "$PID_FILE"
            exit 1
        fi
    fi

    read -r CURRENT TOTAL <<< "$(get_ninja_progress "$ACTIVE_LOG")"

    if (( TOTAL > 0 )); then
        PROGRESS=$(awk "BEGIN {printf \"%.4f\", $CURRENT / $TOTAL}")
        PROGRESS_PCT=$(awk "BEGIN {printf \"%.1f\", $CURRENT / $TOTAL * 100}")
        PROGRESS_DISPLAY="$CURRENT/$TOTAL ($PROGRESS_PCT%)"
    else
        TIME_PROGRESS=$(awk "BEGIN {p = $ELAPSED / $MAX_WAIT; if (p > 1) p = 1; printf \"%.4f\", p}")
        PROGRESS="$TIME_PROGRESS"
        PROGRESS_PCT=$(awk "BEGIN {printf \"%.1f\", $TIME_PROGRESS * 100}")
        PROGRESS_DISPLAY="~$PROGRESS_PCT% (time-based estimate)"
    fi

    DELAY=$(calculate_delay "$PROGRESS" "$MIN_DELAY" "$MAX_DELAY")

    REMAINING=$((MAX_WAIT - ELAPSED))
    if (( DELAY > REMAINING )); then
        DELAY=$REMAINING
    fi
    if (( DELAY < MIN_DELAY )); then
        DELAY=$MIN_DELAY
    fi

    POLL_COUNT=$((POLL_COUNT + 1))

    LAST_LINE=""
    if [[ -f "$ACTIVE_LOG" ]]; then
        LAST_LINE=$(tail -1 "$ACTIVE_LOG" 2>/dev/null | head -c 80 || echo "")
    fi

    LOG_SIZE="0"
    if [[ -f "$ACTIVE_LOG" ]]; then
        LOG_SIZE=$(du -h "$ACTIVE_LOG" 2>/dev/null | cut -f1 || echo "0")
    fi

    echo -e "${BLUE}[Poll #$POLL_COUNT]${NC} Elapsed: $(format_duration $ELAPSED) | Progress: $PROGRESS_DISPLAY | Next check: ${DELAY}s | Log: $LOG_SIZE"

    sleep "$DELAY"
done
