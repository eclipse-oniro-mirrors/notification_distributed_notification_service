#!/bin/bash
# find_module_libs.sh
# 列举模块产生的所有库及其依赖关系。
#
# 用法: find_module_libs.sh <module_name> [product] [--symbol <name>]
#
# 选项:
#   --symbol <name>  检查特定符号是否被模块库导出
#
# 输出: .so 文件列表 + 所有库的 NEEDED 依赖 + 符号可用性

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/env.sh"

MODULE=""
PRODUCT=""
SYMBOL_QUERY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --symbol) SYMBOL_QUERY="$2"; shift 2 ;;
    --help|-h) sed -n '2,11p' "$0"; exit 0 ;;
    --*) echo "错误: 未知选项 '$1' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$1"; else PRODUCT="$1"; fi; shift ;;
  esac
done

if [ -z "$MODULE" ]; then
  echo "用法: find_module_libs.sh <module_name> [product] [--symbol <name>]" >&2
  echo "示例: find_module_libs.sh distributed_notification_service rk3568" >&2
  exit 1
fi

# 定位 OpenHarmony 根目录
OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录。请设置 OH_ROOT 或在源码树内运行。" >&2; exit 1; }
echo "OpenHarmony 根目录: $OH_ROOT"

# 产品名: 位置参数优先，其次 OH_PRODUCT/自动探测
if [ -z "$PRODUCT" ]; then
  PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 1
fi

OUT_DIR="$OH_ROOT/out/$PRODUCT"
if [ ! -d "$OUT_DIR" ]; then
  echo "错误: $OUT_DIR 不存在。请先编译。" >&2
  exit 1
fi

LLVM_BIN="$OH_ROOT/prebuilts/clang/ohos/linux-x86_64/llvm/bin"
if [ ! -d "$LLVM_BIN" ]; then
  echo "警告: LLVM 工具链未找到于 $LLVM_BIN。使用系统 readelf/nm。" >&2
  LLVM_BIN=""
fi

READELF="${LLVM_BIN:+$LLVM_BIN/llvm-readelf}"
NM="${LLVM_BIN:+$LLVM_BIN/llvm-nm}"
if [ -z "$LLVM_BIN" ]; then
  READELF="readelf"
  NM="nm"
fi

# 收集所有 .so 文件
declare -A SEEN_BASENAMES
UNIQUE_LIBS=()

for search_dir in "$OUT_DIR" "$OUT_DIR/lib.unstripped" "$OUT_DIR/innerkits/ohos-arm"; do
  if [ ! -d "$search_dir" ]; then continue; fi
  while IFS= read -r lib; do
    [ -z "$lib" ] && continue
    bname="$(basename "$lib")"
    if [ -z "${SEEN_BASENAMES[$bname]:-}" ]; then
      UNIQUE_LIBS+=("$lib")
      SEEN_BASENAMES[$bname]=1
    fi
  done < <(find "$search_dir" -maxdepth 4 -type f -name "*.so" -path "*$MODULE*" 2>/dev/null || true)
done

echo "=== 模块 $MODULE 产生的原生库 ==="
if [ ${#UNIQUE_LIBS[@]} -eq 0 ]; then
  echo "  (未找到 — 模块可能未为产品 '$PRODUCT' 编译)"
  echo "  搜索路径: $OUT_DIR, $OUT_DIR/lib.unstripped, $OUT_DIR/innerkits/ohos-arm"
else
  for lib in "${UNIQUE_LIBS[@]}"; do
    size=$(stat -c%s "$lib" 2>/dev/null || echo "?")
    echo "  $lib ($size 字节)"
  done
fi
echo "  总计: ${#UNIQUE_LIBS[@]} 个唯一库"

echo ""
echo "=== NEEDED 依赖（来自所有库） ==="
declare -A ALL_NEEDED
for lib in "${UNIQUE_LIBS[@]}"; do
  deps=$("$READELF" -d "$lib" 2>/dev/null | grep NEEDED || true)
  while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    dep_name="$(echo "$dep" | awk '{print $NF}' | tr -d '[]')"
    if [ -z "${ALL_NEEDED[$dep_name]:-}" ]; then
      ALL_NEEDED[$dep_name]="$(basename "$lib")"
    fi
  done < <(echo "$deps")
done

if [ ${#ALL_NEEDED[@]} -eq 0 ]; then
  echo "  (未找到 NEEDED 依赖)"
else
  for k in $(echo "${!ALL_NEEDED[@]}" | tr ' ' '\n' | sort); do
    echo "  $k (来自 ${ALL_NEEDED[$k]})"
  done
fi
echo "  总计: ${#ALL_NEEDED[@]} 个唯一 NEEDED 依赖"

echo ""
if [ -n "$SYMBOL_QUERY" ]; then
  echo "=== 符号检查: $SYMBOL_QUERY ==="
  SYMBOLS_FOUND=0
  for lib in "${UNIQUE_LIBS[@]}"; do
    if "$NM" -D "$lib" 2>/dev/null | grep -qE "$SYMBOL_QUERY"; then
      matches=$("$NM" -D "$lib" 2>/dev/null | grep -E "$SYMBOL_QUERY" | awk '{print $3}')
      echo "  $(basename "$lib"): $matches"
      SYMBOLS_FOUND=1
    fi
  done
  if [ "$SYMBOLS_FOUND" -eq 0 ]; then
    echo "  (未找到匹配符号)"
  fi
else
  SYMBOLS_FOUND=0
  echo "=== 符号检查: 跳过 (使用 --symbol <name> 启用) ==="
fi

echo ""
echo "=== 总结 ==="
echo "  库: ${#UNIQUE_LIBS[@]}"
echo "  NEEDED 依赖: ${#ALL_NEEDED[@]}"
echo "  符号命中: $SYMBOLS_FOUND"