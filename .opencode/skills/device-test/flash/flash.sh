#!/bin/bash
# ============================================================================
# flash.sh - 刷机统一入口：识别设备类型 → 分发到对应单设备模块
#
# 架构: 刷机全部经反向隧道在 Windows 侧执行（板子接 Windows 机的 USB 上）。
#       服务器负责解析/编排，Windows 侧只执行刷机程序。
#
# 识别依据（镜像目录特征 = 你要刷的产物，构建什么板就刷什么板）:
#   out/<product>/packages/phone/images/ 下
#     *.pac          → wukong100 模块（Unisoc/SPRD 协议栈, spd_dump.exe）
#     parameter.txt  → rk3568   模块（Rockchip 协议栈, rkdeveloptool.exe）
#
# 用法: flash.sh [product] [--dry-run] [--yes] [...其余参数透传给设备模块]
#   product  产品名（默认自动探测；多产品时须 OH_PRODUCT/env.conf 指定）
#   --dry-run 只打印操作计划（设备模块各自的预演），不执行
#   --yes     跳过交互确认（主流程 verify.sh 自动化用）
#
# 各模块内置环境三查（工具动态发现/驱动/镜像），不满足时按
# references/flash-env.md 对应小节提示准备环境后重试。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SKILL_DIR/lib/env.sh"

PRODUCT=""
PASSTHRU=()
for arg in "$@"; do
  case "$arg" in
    --help|-h) sed -n '2,21p' "$0"; exit 0 ;;
    --*) PASSTHRU+=("$arg") ;;
    *)  if [ -z "$PRODUCT" ]; then PRODUCT="$arg"; else PASSTHRU+=("$arg"); fi ;;
  esac
done

OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录（在源码树内运行或设 OH_ROOT）" >&2; exit 1; }
if [ -z "$PRODUCT" ]; then
  PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 1
fi
IMAGES_DIR="$OH_ROOT/out/$PRODUCT/packages/phone/images"
[ -d "$IMAGES_DIR" ] || { echo "错误: $IMAGES_DIR 不存在（该产品未编译出镜像）" >&2; exit 1; }

# ---------- 设备类型识别 ----------
if ls "$IMAGES_DIR"/*.pac > /dev/null 2>&1; then
  DEVICE="wukong100"
elif [ -f "$IMAGES_DIR/parameter.txt" ]; then
  DEVICE="rk3568"
else
  echo "错误: 无法识别 $IMAGES_DIR 镜像的设备类型（无 *.pac 也无 parameter.txt）。" >&2
  echo "  wukong100 模块需 *.pac；rk3568 模块需 parameter.txt。新设备接入见 references/flash-env.md" >&2
  exit 1
fi

echo "产品: $PRODUCT    设备类型: $DEVICE    镜像: $IMAGES_DIR"
echo ""

# ---------- 分发到单设备模块 ----------
exec bash "$SCRIPT_DIR/$DEVICE/flash.sh" "${PASSTHRU[@]}"
