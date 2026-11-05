#!/bin/bash
# ============================================================================
# collect_report.sh - 回收 Windows 侧最新测试报告并解析
# 用法: collect_report.sh [tdd|acts]   # 默认 tdd
# ============================================================================
source "$(dirname "$0")/common.sh"
require_config || exit 1
cd "$CODE_DIR" || exit 1
check_tunnel || exit 1
collect_report "${1:-tdd}"
