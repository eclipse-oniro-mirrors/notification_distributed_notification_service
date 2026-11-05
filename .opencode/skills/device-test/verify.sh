#!/bin/bash
# ============================================================================
# verify.sh - 主流程入口：①同步检查 → (需刷机则)②刷机 → ③测试
#
# 架构: 服务器编排。板子接 Windows 时全程经反向隧道（hdc/刷机均在 Windows 侧执行）；
#       板子接服务器时自动走直连链路。
#
# 用法: verify.sh <module> [--no-flash] [--flash-if-needed] [--type=...]
#                     [--gtest-filter=<p>] [--skip-test] [...其余透传给 run_module_tests]
#   <module>          模块名（如 distributed_notification_service）
#   --no-flash        需刷机时不刷，报告后退出（默认行为即如此；显式声明）
#   --flash-if-needed 需刷机时自动执行 flash/flash.sh（刷完复验同步再跑测试）
#   --skip-test       只做①②（同步检查/刷机），不跑测试
#   其余参数(--type/--gtest-filter/...) 透传给 push/run（直连链路时）
#
# 退出码: 0=同步且测试通过  1=需刷机/测试失败/刷机失败  2=用法错误
# ============================================================================
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SKILL_DIR/lib/env.sh"

MODULE=""
DO_FLASH=0
SKIP_TEST=0
PASSTHRU=()
for arg in "$@"; do
  case "$arg" in
    --help|-h)        sed -n '2,19p' "$0"; exit 0 ;;
    --flash-if-needed) DO_FLASH=1 ;;
    --no-flash)       DO_FLASH=0 ;;
    --skip-test)      SKIP_TEST=1 ;;
    --*)              PASSTHRU+=("$arg") ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$arg"; else PASSTHRU+=("$arg"); fi ;;
  esac
done
[ -n "$MODULE" ] || { echo "用法: verify.sh <module> [--flash-if-needed] [...]" >&2; exit 2; }

OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录" >&2; exit 2; }
PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 2

# ---------- ① 同步检查 ----------
echo "════ ① 同步检查（$MODULE）════"
if bash "$SKILL_DIR/test/check_sync.sh" "$MODULE"; then
    SYNCED=1
else
    rc=$?
    [ "$rc" = "2" ] && exit 2
    SYNCED=0
fi
echo ""

# ---------- ② 刷机（需刷机时） ----------
if [ "$SYNCED" -eq 0 ]; then
    if [ "$DO_FLASH" -eq 0 ]; then
        echo "设备与工作区不同步。自动刷机请加: --flash-if-needed"
        exit 1
    fi
    echo "════ ② 刷机（$PRODUCT，Windows 侧执行）════"
    if ! bash "$SKILL_DIR/flash/flash.sh" "$PRODUCT" --yes; then
        echo "刷机失败——中止主流程" >&2
        exit 1
    fi
    echo ""
    echo "════ ①' 刷后复验同步 ════"
    SYNCED_AFTER=0
    for attempt in 1 2 3; do
        if bash "$SKILL_DIR/test/check_sync.sh" "$MODULE"; then SYNCED_AFTER=1; break; fi
        if [ "$attempt" -lt 3 ]; then
            echo "（第 $attempt 次复验未通过，20s 后重试——设备可能仍在启动中）"
            sleep 20
        fi
    done
    if [ "$SYNCED_AFTER" -ne 1 ]; then
        echo "刷机后仍不同步（镜像与产物可能不同批构建——重新编译后再试）" >&2
        exit 1
    fi
    echo ""
fi

# ---------- ③ 测试 ----------
if [ "$SKIP_TEST" -eq 1 ]; then
    echo "════ 完成（--skip-test，未跑测试）════"
    exit 0
fi
echo "════ ③ 测试（$MODULE，经隧道推送+运行）════"
bash "$SKILL_DIR/test/push_module_tests.sh" "$MODULE" "${PASSTHRU[@]}" --incremental || exit 1
bash "$SKILL_DIR/test/run_module_tests.sh" "$MODULE" "${PASSTHRU[@]}"
