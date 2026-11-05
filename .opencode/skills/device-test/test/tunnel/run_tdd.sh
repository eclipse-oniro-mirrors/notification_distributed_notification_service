#!/bin/bash
# ============================================================================
# run_tdd.sh - TDD 链路：编译 -> 推送 -> 板上执行 -> 回收报告
# 用法: run_tdd.sh <part> [target]
#   part    部件名（如 hitrace）
#   target  单个测试目标（如 HitraceMeterTest）；省略则编并跑该部件全部 UT
# 示例: run_tdd.sh hitrace HitraceMeterTest
# ============================================================================
source "$(dirname "$0")/common.sh"
[ $# -lt 1 ] && { echo "用法: $0 <part> [target]  例: $0 hitrace HitraceMeterTest"; exit 1; }
require_config || exit 1
cd "$CODE_DIR" || exit 1
PART="$1"; TARGET="${2:-}"

# ---------- 前置检查 ----------
check_tunnel || exit 1
check_board || exit 1

# ---------- 编译 ----------
build_one_target() {
    local target="$1"
    echo "[BUILD] TDD $target ..."
    ./build.sh --product-name "$PRODUCT_NAME" --build-target "$target" > "$LOG_DIR/build_${target}.log" 2>&1 || {
        tail -15 "$LOG_DIR/build_${target}.log"; echo "[ERROR] 编译失败"; return 1; }
    local bin; bin=$(find out/$PRODUCT_NAME/tests -name "$target" -type f ! -name "*.txt" | head -1)
    [ -z "$bin" ] && { echo "[ERROR] 未找到产物 $target"; return 1; }
    local rel="${bin#out/$PRODUCT_NAME/tests/}"
    mkdir -p "$DELIVERY/Test/testcase/tests/$(dirname "$rel")"
    cp "$bin" "$DELIVERY/Test/testcase/tests/$rel"
    local p; p=$(find out/$PRODUCT_NAME/tests -name "${target}_path.txt" | head -1)
    [ -n "$p" ] && cp "$p" "$DELIVERY/Test/testcase/tests/$(dirname "$rel")/${target}_path.txt"
    echo "      产物: $rel"
}
if [ -n "$TARGET" ]; then
    build_one_target "$TARGET" || exit 1
else
    mapfile -t stubs < <(find out/$PRODUCT_NAME/tests/unittest/"$PART" -name "*_path.txt" 2>/dev/null | xargs -n1 basename | sed 's/_path\.txt//' | sort -u)
    [ ${#stubs[@]} -eq 0 ] && { echo "[ERROR] 部件 $PART 无 UT 清单(out/$PRODUCT_NAME/tests/unittest/$PART)"; exit 1; }
    echo "[TDD] 部件 $PART 共 ${#stubs[@]} 个测试目标: ${stubs[*]}"
    for t in "${stubs[@]}"; do build_one_target "$t" || exit 1; done
    TARGET="${stubs[0]}"   # 默认跑第一个（全部跑可自行循环）
fi

# ---------- 推送 ----------
echo "[PUSH] 组包推送 TDD kit ..."
tar czf "$LOG_DIR/board_tdd_kit.tar.gz" -C "$SKILL_DIR/test/tunnel/templates" run_tdd.ps1 -C "$DELIVERY" Test || exit 1
[ "$(stat -c%s "$LOG_DIR/board_tdd_kit.tar.gz")" -gt 100 ] || { echo "[ERROR] TDD kit 打包异常(空包)"; exit 1; }
win_ssh "(if not exist $WIN_DIR_BS\\tmp mkdir $WIN_DIR_BS\\tmp)" || exit 1
$SCP_CMD "$LOG_DIR/board_tdd_kit.tar.gz" "$WIN_USER@127.0.0.1:$WIN_TMP/" || exit 1
win_ssh "cd /d $WIN_DIR_BS && tar xzf tmp\\board_tdd_kit.tar.gz && del tmp\\board_tdd_kit.tar.gz" || exit 1

# ---------- 远程执行 ----------
echo "[RUN] 远程执行 TDD: $TARGET"
win_ssh "powershell -ExecutionPolicy Bypass -File $WIN_DIR_BS\\run_tdd.ps1 -Hdc $HDC_EXE -Python $PYTHON_EXE -TestArgs \"run -t UT -ts $TARGET -p $PRODUCT_NAME\"" 2>&1 | tail -8

# ---------- 回收报告 ----------
collect_report tdd
