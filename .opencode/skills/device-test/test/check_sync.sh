#!/bin/bash
# ============================================================================
# check_sync.sh - 主流程步骤①：编译产物与设备 .so md5 对比 → 刷机决策
#
# 基准: out/<product>/packages/phone/{system,sys_prod,vendor}/lib*/ 下的 .so
#       （镜像内容 = 刷机后设备上的真实文件；不用编译中间产物——两者有 strip 差异，直接比对会误报）
#       packages 目录与设备 rootfs 路径镜像对应（packages/phone/system/lib64/x.so ↔ /system/lib64/x.so）
#
# 链路自适应: 板子接服务器→直连 hdc；接 Windows→经隧道
#
# 用法: check_sync.sh <module> [--max-report=<n>]
#       check_sync.sh --all [--max-report=<n>]          （全系统 .so 对比）
#   --max-report  逐文件明细最多列 n 条（默认 20，汇总始终打印）
#
# 退出码: 0=已同步  1=需刷机  2=错误
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SKILL_DIR/lib/env.sh"

MODULE=""
ALL=0
MAX_REPORT=20

for arg in "$@"; do
  case "$arg" in
    --all)          ALL=1 ;;
    --max-report=*) MAX_REPORT="${arg#--max-report=}" ;;
    --help|-h)      sed -n '2,19p' "$0"; exit 0 ;;
    --*)            echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$arg"; fi ;;
  esac
done
if [ "$ALL" -eq 0 ] && [ -z "$MODULE" ]; then
  echo "用法: check_sync.sh <module> [--max-report=<n>]   或   check_sync.sh --all" >&2
  exit 2
fi

# ---------- 环境与基准 ----------
OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录" >&2; exit 2; }
PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 2
PKG_PHONE="$OH_ROOT/out/$PRODUCT/packages/phone"
[ -d "$PKG_PHONE/system" ] || { echo "错误: $PKG_PHONE/system 不存在（产品未打包镜像）" >&2; exit 2; }

# ---------- 收集基准文件（packages 内相对路径） ----------
declare -A REF_FILES   # relpath -> local md5
collect_refs() {
    local f rel
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        rel="${f#"$PKG_PHONE"/}"
        REF_FILES["$rel"]="$(md5sum "$f" | cut -d' ' -f1)"
    done < <(find "$PKG_PHONE"/system/lib* "$PKG_PHONE"/sys_prod/lib* "$PKG_PHONE"/vendor/lib* \
               -type f -name "*.so" 2>/dev/null || true)
}

if [ "$ALL" -eq 1 ]; then
    collect_refs
    SCOPE_DESC="全系统"
else
    # 模块模式: 从产物目录收集模块 so 清单(文件名), 再映射到 packages 镜像内路径
    OUT_DIR="$OH_ROOT/out/$PRODUCT"
    declare -A MOD_NAMES=()
    for search_dir in "$OUT_DIR" "$OUT_DIR/lib.unstripped" "$OUT_DIR/innerkits/ohos-arm"; do
        [ -d "$search_dir" ] || continue
        while IFS= read -r lib; do
            [ -z "$lib" ] && continue
            MOD_NAMES["$(basename "$lib")"]=1
        done < <(find "$search_dir" -maxdepth 4 -type f -name "*.so" -path "*$MODULE*" 2>/dev/null)
    done
    if [ ${#MOD_NAMES[@]} -eq 0 ]; then
        echo "错误: 未找到模块 '$MODULE' 的 .so 产物（未编译?）" >&2
        exit 2
    fi
    local_names="$(printf '%s\n' "${!MOD_NAMES[@]}")"
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        rel="${f#"$PKG_PHONE"/}"
        REF_FILES["$rel"]="$(md5sum "$f" | cut -d' ' -f1)"
    done < <(find "$PKG_PHONE"/system/lib* "$PKG_PHONE"/sys_prod/lib* "$PKG_PHONE"/vendor/lib* \
               -type f -name "*.so" 2>/dev/null | grep -F -f <(printf '%s\n' "${!MOD_NAMES[@]}"))
    SCOPE_DESC="模块 $MODULE"
fi
TOTAL=${#REF_FILES[@]}
[ "$TOTAL" -gt 0 ] || { echo "错误: packages 镜像中未找到可比对的 .so（模块名不匹配?）" >&2; exit 2; }

# ---------- 链路（唯一: 隧道 → Windows hdc） ----------
require_config || exit 2
check_tunnel || exit 2
echo "同步检查: $SCOPE_DESC    产品: $PRODUCT    基准: packages/phone 镜像内容    链路: 隧道(Windows hdc)"
echo ""

# ---------- 设备侧批量 md5（镜像路径直查，分批防命令行超长） ----------
declare -A DEV_MD5
batch=()
flush_batch() {
    [ ${#batch[@]} -eq 0 ] && return 0
    local out
    out="$(win_hdc_shell "md5sum ${batch[*]} 2>/dev/null" | tr -d '\r')"
    while IFS= read -r line; do
        local m p
        m="$(awk '{print $1}' <<< "$line")"
        p="$(awk '{print $2}' <<< "$line")"
        [ -n "$m" ] && [ -n "$p" ] && DEV_MD5["$p"]="$m"   # p 已是绝对路径, 勿再加前导 /
    done <<< "$out"
    batch=()
}
for rel in "${!REF_FILES[@]}"; do
    batch+=("/$rel")
    [ ${#batch[@]} -ge 30 ] && flush_batch
done
flush_batch

# ---------- 对比与报告 ----------
OK=0; MISMATCH=0; MISSING=0
declare -a DETAILS=()
for rel in "${!REF_FILES[@]}"; do
    ref="${REF_FILES[$rel]}"
    dev="${DEV_MD5["/$rel"]:-}"
    if [ -z "$dev" ]; then
        MISSING=$((MISSING + 1))
        DETAILS+=("[设备缺失] /$rel")
    elif [ "$ref" != "$dev" ]; then
        MISMATCH=$((MISMATCH + 1))
        DETAILS+=("[不一致]   /$rel    镜像:${ref:0:12}.. 设备:${dev:0:12}..")
    else
        OK=$((OK + 1))
    fi
done

echo "汇总: 一致 $OK / 不一致 $MISMATCH / 设备缺失 $MISSING / 总计 $TOTAL"
if [ ${#DETAILS[@]} -gt 0 ]; then
    echo "明细（前 $MAX_REPORT 条）:"
    printf '  %s\n' "${DETAILS[@]:0:$MAX_REPORT}"
    [ ${#DETAILS[@]} -gt "$MAX_REPORT" ] && echo "  ...（共 ${#DETAILS[@]} 条，--max-report 调整）"
fi
echo ""
if [ "$MISMATCH" -eq 0 ] && [ "$MISSING" -eq 0 ]; then
    echo "结论: 已同步 ✅（设备与工作区镜像一致，可直接跑测试）"
    exit 0
fi
echo "结论: 需刷机 ❌（设备镜像与工作区不一致——刷机入口: flash/flash.sh $PRODUCT）"
exit 1
