#!/bin/bash
# run_module_tests.sh
# 运行已推送到设备的模块单元测试，生成通过/失败摘要。
#
# 用法: run_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--gtest-filter=<pattern>] [--timeout=<seconds>] [--verbose] [--list] [--list-tests] [--binary=<name>] [log_file]
#
# 选项:
#   --type=<type>                测试类型 (默认: unittest)
#                                 unittest:  单元测试（GTest 格式，解析 PASSED/FAILED）
#                                 moduletest: 模块测试（GTest 格式）
#                                 fuzztest:  模糊测试（无 GTest 输出，只记录是否崩溃）
#                                 benchmark: 性能基准测试（无 GTest 输出）
#                                 all: 运行所有类型
#   --gtest-filter=<pattern>    传递 --gtest_filter 给测试二进制（如 'NotificationSlotTest.*'）
#                                 仅对 unittest/moduletest 有效
#   --timeout=<seconds>         单个测试超时秒数 (默认: unittest/moduletest=120, fuzztest=60)
#   --verbose                   打印完整测试输出
#   --list                      列出设备上的测试二进制但不运行
#   --list-tests                列出指定二进制内的测试用例（使用 --gtest_list_tests）
#                                 需要 --binary 参数，输出含 TestSuiteName.TestCaseName 格式
#   --binary=<name>             只运行指定的测试二进制（如 --binary=notification_service_test）

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/env.sh"

MODULE=""
TEST_TYPE="unittest"
GTEST_FILTER=""
TIMEOUT=""
VERBOSE=0
LIST_ONLY=0
LIST_TESTS=0
BINARY=""
LOG_FILE=""
DEFAULT_TIMEOUT_UNITTEST=120
DEFAULT_TIMEOUT_MODULETEST=120
DEFAULT_TIMEOUT_FUZZTEST=60
DEFAULT_TIMEOUT_BENCHMARK=60

for arg in "$@"; do
  case "$arg" in
    --type=*)          TEST_TYPE="${arg#--type=}"; ;;
    --gtest-filter=*)  GTEST_FILTER="${arg#--gtest-filter=}"; ;;
    --gtest_filter=*)  GTEST_FILTER="${arg#--gtest_filter=}"; ;;
    --timeout=*)       TIMEOUT="${arg#--timeout=}"; ;;
    --verbose)         VERBOSE=1 ;;
    --list)            LIST_ONLY=1 ;;
    --list-tests)      LIST_TESTS=1 ;;
    --binary=*)        BINARY="${arg#--binary=}"; ;;
    --help|-h)         sed -n '2,20p' "$0"; exit 0 ;;
    --*)               echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$arg"; else LOG_FILE="$arg"; fi ;;
  esac
done

if [ -z "$MODULE" ]; then
  echo "用法: run_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--gtest-filter=<pattern>] [--timeout=<seconds>] [--verbose] [--list] [--list-tests] [--binary=<name>] [log_file]" >&2
  exit 1
fi

VALID_TYPES="unittest moduletest fuzztest benchmark all"
if ! echo "$VALID_TYPES" | grep -qw "$TEST_TYPE"; then
  echo "错误: 无效测试类型 '$TEST_TYPE'。可选: unittest, moduletest, fuzztest, benchmark, all" >&2
  exit 1
fi

DEVICE_TEST_BASE="/data/local/tmp"

# 设置默认超时
if [ -z "$TIMEOUT" ]; then
  case "$TEST_TYPE" in
    unittest)    TIMEOUT=$DEFAULT_TIMEOUT_UNITTEST ;;
    moduletest)  TIMEOUT=$DEFAULT_TIMEOUT_MODULETEST ;;
    fuzztest)    TIMEOUT=$DEFAULT_TIMEOUT_FUZZTEST ;;
    benchmark)   TIMEOUT=$DEFAULT_TIMEOUT_BENCHMARK ;;
    all)         TIMEOUT=$DEFAULT_TIMEOUT_UNITTEST ;;
  esac
fi

if [ -z "$LOG_FILE" ]; then
  LOG_FILE="/tmp/${MODULE}_${TEST_TYPE}_test_$(date +%Y%m%d_%H%M%S).log"
fi

# 链路（隧道）与设备探活
require_config || exit 1
check_tunnel || exit 1
dt_probe_device || exit 1

# 设备库目录: OH_DEVICE_LIB_DIR 优先(冒号分隔多个)，未设置时按设备架构自动探测
# (aarch64→/system/lib64[/platformsdk]，32位→/system/lib[/platformsdk])；依赖 HDC，须在其后
if [ -n "${OH_DEVICE_LIB_DIR:-}" ]; then
  DEVICE_LIB_PATH="$OH_DEVICE_LIB_DIR"
else
  DEVICE_LIB_PATH="$(dt_device_lib_dirs)"
fi

# 运行指定类型的测试
run_type() {
  local type="$1"
  local device_dir="$DEVICE_TEST_BASE/${MODULE}_${type}"
  local effective_timeout="$TIMEOUT"
  case "$type" in
    fuzztest)  effective_timeout="${TIMEOUT:-$DEFAULT_TIMEOUT_FUZZTEST}" ;;
    benchmark) effective_timeout="${TIMEOUT:-$DEFAULT_TIMEOUT_BENCHMARK}" ;;
    *)         effective_timeout="${TIMEOUT:-$DEFAULT_TIMEOUT_UNITTEST}" ;;
  esac

  # 列举设备上的测试
  local TEST_LIST
  TEST_LIST=$(win_hdc_shell "ls $device_dir 2>/dev/null" | tr -d '\r' | \
    grep -v '^lib' | grep -v '\.so$' | grep -v '\.abc$' | grep -v '\.txt$' | grep -v '\.xml$' | sort || true)

  # --binary 过滤：只保留指定二进制
  if [ -n "$BINARY" ]; then
    TEST_LIST=$(echo "$TEST_LIST" | grep -x "$BINARY" || true)
  fi

  local TOTAL
  TOTAL=$(echo "$TEST_LIST" | grep -c . || true)

  if [ "$TOTAL" -eq 0 ]; then
    if [ -n "$BINARY" ]; then
      echo "$device_dir 中未找到二进制 '$BINARY'" >&2
    else
      echo "$device_dir 中未找到 $type 测试" >&2
      echo "是否已推送？请使用: push_module_tests.sh $MODULE --type=$type --tests-only" >&2
    fi
    return 0
  fi

  # --list-tests 模式：列出二进制内的测试用例
  if [ "$LIST_TESTS" -eq 1 ]; then
    for t in $TEST_LIST; do
      echo "=== $t ==="
      win_hdc_shell "cd $device_dir && LD_LIBRARY_PATH=$DEVICE_LIB_PATH:$device_dir ./$t --gtest_list_tests 2>&1" | tr -d '\r'
      echo ""
    done
    return 0
  fi

  # 列表模式
  if [ "$LIST_ONLY" -eq 1 ]; then
    echo "$device_dir 中的 $type 测试 ($TOTAL 个二进制):"
    for t in $TEST_LIST; do
      echo "  $t"
    done
    return 0
  fi

  echo ""
  echo "=== 运行 $type 测试 ($TOTAL 个二进制) ==="
  echo "  gtest_filter: ${GTEST_FILTER:-'(全部)'}"
  echo "  超时: $effective_timeout 秒/二进制"
  echo "  日志: $LOG_FILE"

  local TYPE_PASS=0
  local TYPE_FAIL=0
  local TYPE_CRASH=0
  local TYPE_TIMEOUT=0
  local FAIL_FILES=""
  local CRASH_FILES=""
  local TIMEOUT_FILES=""
  local I=0

  for t in $TEST_LIST; do
    I=$((I+1))
    echo "[$I/$TOTAL] $t"

    # 构建设备端命令参数
    # hdc shell 传参时引号嵌套极易出错，采用分步方式避免：
    # 1. cd 到测试目录
    # 2. 设置 LD_LIBRARY_PATH
    # 3. 执行测试
    local GTEST_ARG=""
    if [ -n "$GTEST_FILTER" ] && [ "$type" != "fuzztest" ] && [ "$type" != "benchmark" ]; then
      GTEST_ARG="--gtest_filter=$GTEST_FILTER"
    fi

    local OUTPUT=""
    local CRASH_REASON=""
    local TIMED_OUT=0

    # 设备端超时（timeout 不能直接执行 cd 等内建命令）
    # 方案：先 cd + export，再用 timeout 执行测试
    # 若设备无 timeout 命令，主机侧用 `timeout` 兜底（留 15s 缓冲给 hdc 通信开销）
    local HAS_TIMEOUT=0
    if win_hdc_shell "which timeout" 2>/dev/null | tr -d '\r' | grep -q timeout; then
      HAS_TIMEOUT=1
    fi

    local HOST_TIMEOUT_KILLED=0
    local RC=0
    if [ "$HAS_TIMEOUT" -eq 1 ]; then
      OUTPUT=$(win_hdc_shell "cd $device_dir && export LD_LIBRARY_PATH=$DEVICE_LIB_PATH:$device_dir && timeout $effective_timeout ./$t $GTEST_ARG 2>&1" 2>/dev/null) || RC=$?
      # 设备端 timeout 超时返回 124；hdc 通常透传该退出码
      [ "$RC" -eq 124 ] && TIMED_OUT=1
    else
      # 主机侧兜底: 超时后由主机 kill hdc 进程，设备上测试可能残留（dev 工具可接受）
      # 注意: 不能用 `|| true`，否则会吞掉 timeout 的退出码 124
      local HOST_LIMIT=$((effective_timeout + 15))
      OUTPUT=$(win_hdc_timeout "$HOST_LIMIT" "cd $device_dir && export LD_LIBRARY_PATH=$DEVICE_LIB_PATH:$device_dir && ./$t $GTEST_ARG 2>&1" 2>/dev/null) || RC=$?
      # 注: 本脚本头部为 `set -uo pipefail`（无 -e），故非零退出码不会中止脚本
      if [ "$RC" -eq 124 ]; then
        HOST_TIMEOUT_KILLED=1
      fi
    fi

    # 主机侧兜底超时触发时，直接标记为 TIMED_OUT
    if [ "$HOST_TIMEOUT_KILLED" -eq 1 ]; then
      TIMED_OUT=1
      OUTPUT="[主机侧兜底超时] 测试 $t 在 ${HOST_LIMIT}s 内未完成，已由主机强制终止。$OUTPUT"
    fi

    echo "--- $t ($type) ---" >> "$LOG_FILE"
    echo "$OUTPUT" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    # 检查崩溃信号
    if echo "$OUTPUT" | grep -q "signal 11\|Segmentation fault"; then
      CRASH_REASON="SIGSEGV"
    elif echo "$OUTPUT" | grep -q "signal 6\|Aborted"; then
      CRASH_REASON="SIGABRT"
    elif echo "$OUTPUT" | grep -q "signal 9\|Killed"; then
      if echo "$OUTPUT" | grep -qi "timed out\|timeout"; then
        TIMED_OUT=1
      else
        CRASH_REASON="SIGKILL"
      fi
    fi

    # fuzztest/benchmark: 只记录是否崩溃，不解析 GTest 输出
    if [ "$type" = "fuzztest" ] || [ "$type" = "benchmark" ]; then
      if [ -n "$CRASH_REASON" ]; then
        echo "  崩溃 ($CRASH_REASON)"
        TYPE_CRASH=$((TYPE_CRASH + 1))
        CRASH_FILES="$CRASH_FILES $t"
      elif [ "$TIMED_OUT" -eq 1 ]; then
        echo "  超时"
        TYPE_TIMEOUT=$((TYPE_TIMEOUT + 1))
        TIMEOUT_FILES="$TIMEOUT_FILES $t"
      else
        # fuzztest/benchmark 正常退出视为通过
        echo "  通过 (正常退出)"
        TYPE_PASS=$((TYPE_PASS + 1))
      fi
    else
      # unittest/moduletest: 解析 GTest PASSED/FAILED 计数
      local PASSED=$(echo "$OUTPUT" | grep '\[  PASSED  \]' | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) print $i}' | tail -1 || true)
      local FAILED=$(echo "$OUTPUT" | grep '\[  FAILED  \]' | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) print $i}' | head -1 || true)
      PASSED=${PASSED:-0}
      FAILED=${FAILED:-0}
      # 无 PASSED 汇总行 = 测试没跑完（卡死/被 kill），绝不能当成"0 通过"的通过
      local HAS_SUMMARY=0
      grep -q '\[  PASSED  \]' <<< "$OUTPUT" && HAS_SUMMARY=1

      if [ "$TIMED_OUT" -eq 1 ]; then
        echo "  超时 (超过 $effective_timeout 秒)"
        TYPE_TIMEOUT=$((TYPE_TIMEOUT + 1))
        TIMEOUT_FILES="$TIMEOUT_FILES $t"
        TYPE_PASS=$((TYPE_PASS + PASSED))
        TYPE_FAIL=$((TYPE_FAIL + FAILED))
      elif [ -n "$CRASH_REASON" ]; then
        echo "  崩溃 ($CRASH_REASON) — 崩溃前通过 $PASSED"
        TYPE_CRASH=$((TYPE_CRASH + 1))
        CRASH_FILES="$CRASH_FILES $t"
        TYPE_PASS=$((TYPE_PASS + PASSED))
        TYPE_FAIL=$((TYPE_FAIL + FAILED))
      elif [ "$FAILED" -gt 0 ]; then
        echo "  失败: $FAILED 个失败, $PASSED 个通过"
        TYPE_FAIL=$((TYPE_FAIL + FAILED))
        TYPE_PASS=$((TYPE_PASS + PASSED))
        FAIL_FILES="$FAIL_FILES $t"
        if [ "$VERBOSE" -eq 1 ]; then
          echo "$OUTPUT" | grep '\[  FAILED  \]' | while read line; do echo "    $line"; done
        fi
      elif [ "$HAS_SUMMARY" -eq 0 ]; then
        echo "  异常: 用例未跑完（无 PASSED 汇总行，疑似卡死/被中止）"
        TYPE_FAIL=$((TYPE_FAIL + 1))
        FAIL_FILES="$FAIL_FILES $t"
      else
        echo "  通过: $PASSED"
        TYPE_PASS=$((TYPE_PASS + PASSED))
      fi
    fi

    if [ "$VERBOSE" -eq 1 ] && [ -z "$CRASH_REASON" ] && [ "$TIMED_OUT" -eq 0 ]; then
      echo "$OUTPUT" | tail -5
    fi
  done

  echo ""
  echo "=== $type 测试结果 ==="
  echo "  通过:   $TYPE_PASS"
  echo "  失败:   $TYPE_FAIL"
  echo "  崩溃:   $TYPE_CRASH"
  echo "  超时:   $TYPE_TIMEOUT"
  # 通过率分母纳入崩溃/超时（崩溃二进制的用例计数未知，按 1 个失败当量计入），
  # 避免出现"5 个二进制中 2 通过 3 崩溃 → 通过率 100%"的误导。
  local TOTAL_RUN=$((TYPE_PASS + TYPE_FAIL + TYPE_CRASH + TYPE_TIMEOUT))
  if [ "$TOTAL_RUN" -gt 0 ]; then
    local RATE=$(awk "BEGIN {printf \"%.1f\", $TYPE_PASS/$TOTAL_RUN*100}")
    echo "  通过率: $RATE% (通过/总数=$TYPE_PASS/$TOTAL_RUN)"
  fi
  if [ -n "$FAIL_FILES" ]; then echo "  失败文件: $FAIL_FILES"; fi
  if [ -n "$CRASH_FILES" ]; then echo "  崩溃文件: $CRASH_FILES"; fi
  if [ -n "$TIMEOUT_FILES" ]; then echo "  超时文件: $TIMEOUT_FILES"; fi

  # 累加全局计数
  GLOBAL_PASS=$((GLOBAL_PASS + TYPE_PASS))
  GLOBAL_FAIL=$((GLOBAL_FAIL + TYPE_FAIL))
  GLOBAL_CRASH=$((GLOBAL_CRASH + TYPE_CRASH))
  GLOBAL_TIMEOUT=$((GLOBAL_TIMEOUT + TYPE_TIMEOUT))
  GLOBAL_FAIL_FILES="$GLOBAL_FAIL_FILES $FAIL_FILES"
  GLOBAL_CRASH_FILES="$GLOBAL_CRASH_FILES $CRASH_FILES"
  GLOBAL_TIMEOUT_FILES="$GLOBAL_TIMEOUT_FILES $TIMEOUT_FILES"
}

GLOBAL_PASS=0
GLOBAL_FAIL=0
GLOBAL_CRASH=0
GLOBAL_TIMEOUT=0
GLOBAL_FAIL_FILES=""
GLOBAL_CRASH_FILES=""
GLOBAL_TIMEOUT_FILES=""

echo "运行模块 '$MODULE' 的测试..."
echo "  测试类型: $TEST_TYPE"
echo "==========================================" > "$LOG_FILE"

if [ "$TEST_TYPE" = "all" ]; then
  for t in unittest moduletest fuzztest benchmark; do
    run_type "$t"
  done
else
  run_type "$TEST_TYPE"
fi

echo ""
echo "=========================================="
echo "总通过:   $GLOBAL_PASS"
echo "总失败:   $GLOBAL_FAIL"
echo "总崩溃:   $GLOBAL_CRASH"
echo "总超时:   $GLOBAL_TIMEOUT"
TOTAL_ALL=$((GLOBAL_PASS + GLOBAL_FAIL + GLOBAL_CRASH + GLOBAL_TIMEOUT))
if [ "$TOTAL_ALL" -gt 0 ]; then
  RATE=$(awk "BEGIN {printf \"%.1f\", $GLOBAL_PASS/$TOTAL_ALL*100}")
  echo "通过率:   $RATE% (通过/总数=$GLOBAL_PASS/$TOTAL_ALL)"
else
  echo "通过率:   N/A"
fi
echo "=========================================="
if [ -n "$GLOBAL_FAIL_FILES" ]; then echo "失败文件: $GLOBAL_FAIL_FILES"; fi
if [ -n "$GLOBAL_CRASH_FILES" ]; then echo "崩溃文件: $GLOBAL_CRASH_FILES"; fi
if [ -n "$GLOBAL_TIMEOUT_FILES" ]; then echo "超时文件: $GLOBAL_TIMEOUT_FILES"; fi
echo "完整日志: $LOG_FILE"

if [ "$GLOBAL_FAIL" -gt 0 ] || [ "$GLOBAL_CRASH" -gt 0 ] || [ "$GLOBAL_TIMEOUT" -gt 0 ]; then
  exit 1
fi
exit 0