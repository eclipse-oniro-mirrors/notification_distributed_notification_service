#!/bin/bash
# ============================================================================
# check.sh - RK3568 测试环境自检（隧道 / 板子 / Windows 依赖）
# 用法: check.sh
# ============================================================================
source "$(dirname "$0")/common.sh"
require_config || exit 1
cd "$CODE_DIR" || exit 1
run_env_check
