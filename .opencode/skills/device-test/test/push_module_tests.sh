#!/bin/bash
# push_module_tests.sh
# 推送模块共享库和测试二进制到 ARM 设备。
#
# 架构: 服务器不连接设备——所有设备访问经反向隧道在 Windows 侧 hdc 执行。
# 传输设计(批量): 收集清单 → 一次设备探测(路径/增量) → tar+scp 到 Windows staging
#   → 一次 win_ssh for 循环批量 hdc file send → 批量 md5 校验。全过程 ~10 次隧道往返。
#
# 用法: push_module_tests.sh <module_name> [--type=unittest|moduletest|fuzztest|benchmark|all] [--incremental] [--libs-only] [--tests-only] [--lib=<name>] [--remount]
#
#   --type=<type>   测试类型过滤 (默认: unittest)
#   --incremental   只推送本地时间戳 > 设备时间戳的文件
#   --libs-only     只推送共享库（跳过测试二进制）
#   --tests-only    只推送测试二进制（跳过共享库）
#   --lib=<name>    只推送文件名匹配的库（配合 --libs-only，用于单库诊断更新）
#   --remount       强制重新挂载系统分区为可写（已可写时跳过）
#
# 库推送安全设计（与 push_so.sh 同策略）:
#   - 每个库在板上 find 实际路径后覆盖（同库多处命中逐处覆盖），未找到按新库落默认目录
#   - 覆盖前备份到 /data/backup_*，覆盖后双端 md5 校验，失败即报错（exit 1）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/env.sh"

MODULE=""
TEST_TYPE="unittest"
INCREMENTAL=0
LIBS_ONLY=0
TESTS_ONLY=0
FORCE_REMOUNT=0
LIB_FILTER=""

for arg in "$@"; do
  case "$arg" in
    --type=*)       TEST_TYPE="${arg#--type=}"; ;;
    --incremental)  INCREMENTAL=1 ;;
    --libs-only)    LIBS_ONLY=1 ;;
    --tests-only)   TESTS_ONLY=1 ;;
    --lib=*)        LIB_FILTER="${arg#--lib=}"; ;;
    --remount)      FORCE_REMOUNT=1 ;;
    --help|-h)      sed -n '2,23p' "$0"; exit 0 ;;
    --*)            echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)  if [ -z "$MODULE" ]; then MODULE="$arg"; fi ;;
  esac
done

if [ -z "$MODULE" ]; then
  echo "用法: push_module_tests.sh <module_name> [--type=...] [--incremental] [--libs-only] [--tests-only] [--lib=<name>] [--remount]" >&2
  echo "示例: push_module_tests.sh distributed_notification_service --type=unittest" >&2
  exit 1
fi

VALID_TYPES="unittest moduletest fuzztest benchmark all"
if ! echo "$VALID_TYPES" | grep -qw "$TEST_TYPE"; then
  echo "错误: 无效测试类型 '$TEST_TYPE'。可选: unittest, moduletest, fuzztest, benchmark, all" >&2
  exit 1
fi

if [ "$LIBS_ONLY" -eq 1 ] && [ "$TESTS_ONLY" -eq 1 ]; then
  echo "错误: --libs-only 和 --tests-only 不能同时使用" >&2
  exit 1
fi

# ---------- 环境解析（本地） ----------
OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录。请设置 OH_ROOT 或在源码树内运行。" >&2; exit 1; }
echo "OpenHarmony 根目录: $OH_ROOT"

PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 1
echo "产品: $PRODUCT"

OUT_DIR="$OH_ROOT/out/$PRODUCT"
if [ ! -d "$OUT_DIR" ]; then
  echo "错误: $OUT_DIR 不存在。请先编译。" >&2
  exit 1
fi

# ---------- 链路与设备（隧道） ----------
require_config || exit 1
check_tunnel || exit 1
dt_probe_device || exit 1

DEVICE_LIB_DIR="${OH_DEVICE_LIB_DIR:-$(dt_device_lib_dirs | cut -d: -f1)}"
PKG_PHONE="$OH_ROOT/out/$PRODUCT/packages/phone"
echo "设备库目录(默认落位): $DEVICE_LIB_DIR"
echo "Windows staging: $WIN_TMP"

DEVICE_TEST_BASE="/data/local/tmp"

# ---------- 分区重挂载（如需） ----------
check_rw() {
  win_hdc_shell "mount | grep ' / ' | grep -q 'rw,'" > /dev/null 2>&1
}
if [ "$FORCE_REMOUNT" -eq 1 ] || ! check_rw; then
  echo "将系统分区重新挂载为可写..."
  win_hdc target mount > /dev/null 2>&1 || true
  if ! check_rw; then
    win_hdc_shell "mount -o remount,rw /" > /dev/null 2>&1 || true
  fi
  if ! check_rw; then
    echo "错误: 系统分区仍为只读。库推送将失败。" >&2
    exit 1
  fi
fi

# ---------- staging 助手 ----------
STAGE_WIN_BS="$WIN_DIR_BS\\tmp\\push_${MODULE}"
stage_pkg() {   # stage_pkg <清单文件> — 按清单打包本地文件→scp→Windows 解包到 staging
  local files_list="$1" pkg="$LOG_DIR/push_stage.tar.gz" f
  rm -rf "$LOG_DIR/push_stage" && mkdir -p "$LOG_DIR/push_stage"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ ! -f "$f" ]; then
      echo "错误: 清单内文件不存在: $f（中止——不做无源安装）" >&2
      return 1
    fi
    cp -f "$f" "$LOG_DIR/push_stage/"
  done < "$files_list"
  tar czf "$pkg" -C "$LOG_DIR/push_stage" . || return 1
  win_ssh "if exist $STAGE_WIN_BS rd /s /q $STAGE_WIN_BS & (if not exist $STAGE_WIN_BS mkdir $STAGE_WIN_BS)" > /dev/null || return 1
  $SCP_CMD "$pkg" "$WIN_USER@127.0.0.1:$WIN_TMP/push_stage.tar.gz" || return 1
  win_ssh "cd /d $STAGE_WIN_BS && tar xzf $WIN_DIR_BS\\tmp\\push_stage.tar.gz && del $WIN_DIR_BS\\tmp\\push_stage.tar.gz" > /dev/null || return 1
  rm -rf "$LOG_DIR/push_stage" "$pkg"
}

# ---------- 库推送（批量隧道） ----------
push_libs() {
  echo ""
  echo "=== 推送模块库 ==="

  # 1) 收集本地库（去重）
  local -a LIBS=()
  local -a SEEN=()
  local search_dir lib bname seen
  for search_dir in "$OUT_DIR" "$OUT_DIR/lib.unstripped" "$OUT_DIR/innerkits/ohos-arm"; do
    [ -d "$search_dir" ] || continue
    while IFS= read -r lib; do
      [ -z "$lib" ] && continue
      bname="$(basename "$lib")"
      if [ -n "$LIB_FILTER" ] && [[ "$bname" != *"$LIB_FILTER"* ]]; then continue; fi
      seen=0
      for s in "${SEEN[@]}"; do [ "$s" = "$bname" ] && seen=1 && break; done
      if [ "$seen" -eq 0 ]; then
        LIBS+=("$lib"); SEEN+=("$bname")
      fi
    done < <(find "$search_dir" -maxdepth 4 -type f -name "*.so" -path "*$MODULE*" 2>/dev/null)
  done
  if [ ${#LIBS[@]} -eq 0 ]; then
    echo "  未找到模块 '$MODULE' 的 .so 文件。"
    return 0
  fi

  # 2) 一次设备 find 探测所有库的实际路径
  echo "  探测板上实际路径（一次批量探测 ${#LIBS[@]} 个库）..."
  local find_expr="" name
  for lib in "${LIBS[@]}"; do
    name="$(basename "$lib")"
    [ -n "$find_expr" ] && find_expr+=" -o "
    find_expr+="-name '$name'"
  done
  local -A DEV_PATHS=()   # name -> 实际路径列表(空格分隔)
  local line hit
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    name="$(basename "$line")"
    DEV_PATHS["$name"]="${DEV_PATHS[$name]:-} $line"
  done < <(win_hdc_shell "find /system /vendor /sys_prod /chip_prod \( $find_expr \) 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -v "^$" | grep -v "find:" | sort -u)

  # 3) 增量判定（一次批量 stat 所有目标）
  local -a ALL_DSTS=()
  local -A LIB_DSTS=() LIB_LOCAL_MD5=()
  for lib in "${LIBS[@]}"; do
    name="$(basename "$lib")"
    LIB_LOCAL_MD5["$name"]="$(md5sum "$lib" | cut -d' ' -f1)"
    if [ -n "${DEV_PATHS[$name]:-}" ]; then
      LIB_DSTS["$name"]="${DEV_PATHS[$name]}"
    else
      # 新库落位: packages 镜像树定位(镜像规则, 与 check_sync 一致) > 默认目录首个
      local p
      p="$(find "$PKG_PHONE"/system/lib* "$PKG_PHONE"/vendor/lib* -name "$name" 2>/dev/null | head -1)"
      if [ -n "$p" ]; then
        LIB_DSTS["$name"]="/${p#"$PKG_PHONE"/}"
        echo "  [新库] $name 板上未找到，按包镜像树落 /${p#"$PKG_PHONE"/}"
      else
        LIB_DSTS["$name"]="$DEVICE_LIB_DIR/$name"
        echo "  [新库] $name 板上未找到且包镜像树无此库，落默认 $DEVICE_LIB_DIR"
      fi
    fi
    read -r -a ds <<< "${LIB_DSTS[$name]}"
    ALL_DSTS+=("${ds[@]}")
  done
  local -A DEV_MTIME=()
  if [ "$INCREMENTAL" -eq 1 ] && [ ${#ALL_DSTS[@]} -gt 0 ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local m p
      m="$(awk '{print $1}' <<< "$line")"
      p="$(awk '{print $2}' <<< "$line")"
      DEV_MTIME["$p"]="$m"
    done < <(win_hdc_shell "stat -c '%Y %n' ${ALL_DSTS[*]} 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+ /')
  fi

  # 4) 过滤需推送的库
  local -a PUSH_LIBS=()
  local skipped=0 all_fresh
  for lib in "${LIBS[@]}"; do
    name="$(basename "$lib")"
    local local_ts
    local_ts="$(stat -c '%Y' "$lib" 2>/dev/null || echo 0)"
    all_fresh=1
    local dst
    for dst in ${LIB_DSTS[$name]}; do
      local dev_ts="${DEV_MTIME[$dst]:-0}"
      if [ "$dev_ts" -lt "$local_ts" ] || [ "$dev_ts" -eq 0 ]; then all_fresh=0; break; fi
    done
    if [ "$INCREMENTAL" -eq 1 ] && [ "$all_fresh" -eq 1 ]; then
      skipped=$((skipped + 1))
      continue
    fi
    PUSH_LIBS+=("$lib")
  done

  if [ ${#PUSH_LIBS[@]} -eq 0 ]; then
    echo "  已跳过: $skipped, 总计: ${#LIBS[@]}（全部为最新）"
    return 0
  fi

  # 5) staging 传输（一次 tar+scp+解包）
  printf '%s\n' "${PUSH_LIBS[@]}" > "$LOG_DIR/push_libs.list"
  stage_pkg "$LOG_DIR/push_libs.list" || { echo "错误: staging 传输失败" >&2; return 1; }

  # 6) 一次 win_ssh 批量 file send 到设备 /data/local/tmp（带诊断日志）
  local hdc_cmd="\"$HDC_EXE\""
  [ -n "$TOOLCHAINS_DIR" ] && hdc_cmd="set PATH=$TOOLCHAINS_DIR;%PATH% && $hdc_cmd"
  local send_out
  send_out="$(win_ssh "cd /d $STAGE_WIN_BS && for %f in (*) do $hdc_cmd file send \"%f\" /data/local/tmp/%~nxf" 2>&1 || true)"
  local send_ok
  send_ok="$(grep -ac "FileTransfer finish" <<< "$send_out" || true)"
  echo "[$(date +%T)] file_send: ${send_ok} 个 FileTransfer 确认(应≥${#PUSH_LIBS[@]})" >> "$LOG_DIR/push_debug.log"
  if [ "${send_ok:-0}" -lt "${#PUSH_LIBS[@]}" ]; then
    echo "[$(date +%T)] file_send 输出尾部: $(tail -c 300 <<< "$send_out" | tr -d "\r" | tr "\n" " ")" >> "$LOG_DIR/push_debug.log"
  fi
  # 源存在性抽查（防 cp 无源静默失败）
  local probe_src
  probe_src="$(basename "${PUSH_LIBS[0]}")"
  echo "[$(date +%T)] 源抽查 /data/local/tmp/$probe_src: $(win_hdc_shell "[ -f /data/local/tmp/$probe_src ] && echo OK || echo MISSING" 2>/dev/null | tr -d "\r" | head -1)" >> "$LOG_DIR/push_debug.log"

  # 6.5) 根分区只读时自动 remount rw（新刷机后 / 为 ext4 ro，rm/cp 覆盖库会静默失败）
  local root_mount
  root_mount="$(win_hdc_shell "mount | grep ' / ' | head -1" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$root_mount" == *"(ro,"* ]]; then
    echo "  设备根分区只读，自动 remount rw ..."
    if win_hdc_shell "mount -o remount,rw / 2>/dev/null" > /dev/null 2>&1; then
      echo "  remount rw 成功"
    else
      echo "  警告: remount rw 失败，库覆盖可能失败（需 root 权限）" >&2
    fi
  fi

  # 7) 备份 + 覆盖 + chmod（各一次批量 win_hdc，长命令按 8 段分块防截断）
  #    覆盖采用 rm-then-cp: 被 mmap 中的库(ETXTBSY)裸 cp 会静默失败, rm 后 cp 新建 inode 不受影响
  run_chunked() {   # run_chunked <分段函数名> <数组...> —— 每段一条 win_hdc_shell
    local emit="$1"; shift
    local -a items=("$@") chunk=()
    local it rc
    for it in "${items[@]}"; do
      chunk+=("$it")
      if [ ${#chunk[@]} -ge 8 ]; then
        local cmd; cmd="$($emit "${chunk[@]}")"
        local rc=0
        win_hdc_shell "$cmd" > /dev/null 2>&1 || rc=$?
        echo "[$(date +%T)] chunk(${#chunk[@]}) rc=$rc cmd=${cmd:0:100}..." >> "$LOG_DIR/push_debug.log"
        chunk=()
      fi
    done
    if [ ${#chunk[@]} -gt 0 ]; then
      local cmd; cmd="$($emit "${chunk[@]}")"
      local rc=0
      win_hdc_shell "$cmd" > /dev/null 2>&1 || rc=$?
      echo "[$(date +%T)] chunk(${#chunk[@]}) rc=$rc cmd=${cmd:0:100}..." >> "$LOG_DIR/push_debug.log"
    fi
  }
  emit_backup() {   # emit_backup <dst...> → "cp d1 b1 2>/dev/null; cp d2 b2 ..."
    local out="" d b
    for d in "$@"; do
      b="/data/backup_$(echo "$d" | tr '/' '_')"
      out+="cp '$d' '$b' 2>/dev/null;"
    done
    echo "$out"
  }
  emit_install() {  # emit_install <"name dst"...> → "rm -f dst; cp /data/local/tmp/name dst && chmod 644 dst; ..."
    local out="" nd name dst
    for nd in "$@"; do
      name="${nd%%|*}"; dst="${nd#*|}"
      out+="rm -f '$dst' 2>/dev/null; cp /data/local/tmp/$name '$dst' 2>/dev/null && chmod 644 '$dst';"
    done
    echo "$out"
  }
  local -a BK_ITEMS=() IN_ITEMS=()
  for lib in "${PUSH_LIBS[@]}"; do
    name2="$(basename "$lib")"
    for dst2 in ${LIB_DSTS[$name2]}; do
      BK_ITEMS+=("$dst2")
      IN_ITEMS+=("$name2|$dst2")
    done
  done
  [ ${#BK_ITEMS[@]} -gt 0 ] && run_chunked emit_backup "${BK_ITEMS[@]}"
  [ ${#IN_ITEMS[@]} -gt 0 ] && run_chunked emit_install "${IN_ITEMS[@]}"

  # 8) 批量 md5 校验（分块 win_hdc，防长命令截断）
  local -a VERIFY_DSTS=()
  for lib in "${PUSH_LIBS[@]}"; do
    name2="$(basename "$lib")"
    read -r -a ds <<< "${LIB_DSTS[$name2]}"
    VERIFY_DSTS+=("${ds[@]}")
  done
  local pushed=0 failed=0
  local -A VERIFIED_DSTS=()
  local vchunk=()
  verify_chunk() {
    [ ${#vchunk[@]} -eq 0 ] && return 0
    local line m p vname
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      m="$(awk '{print $1}' <<< "$line")"
      p="$(awk '{print $2}' <<< "$line")"
      vname="$(basename "$p")"
      if [ -n "$m" ] && [ "$m" = "${LIB_LOCAL_MD5[$vname]:-}" ]; then
        echo "  [成功] $vname -> $p (md5 $m)"
        pushed=$((pushed + 1))
      else
        echo "  [失败] $vname -> $p (设备 md5: ${m:-无})" >&2
        failed=$((failed + 1))
      fi
      VERIFIED_DSTS["$p"]=1
    done < <(win_hdc_shell "md5sum ${vchunk[*]} 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -E '^[0-9a-f]{32} ')
    vchunk=()
  }
  for dst in "${VERIFY_DSTS[@]}"; do
    vchunk+=("$dst")
    [ ${#vchunk[@]} -ge 12 ] && verify_chunk
  done
  verify_chunk
  # 设备上无 md5 返回的目标(缺失)计入失败——杜绝"删了没装"被静默漏计
  for dst in "${VERIFY_DSTS[@]}"; do
    if [ -z "${VERIFIED_DSTS[$dst]:-}" ]; then
      echo "  [失败] $(basename "$dst") -> $dst (设备上文件缺失——安装未生效!)" >&2
      failed=$((failed + 1))
    fi
  done

  # 9) 清理设备中转文件
  local rm_names=""
  for lib in "${PUSH_LIBS[@]}"; do rm_names+=" /data/local/tmp/$(basename "$lib")"; done
  win_hdc_shell "rm -f$rm_names" > /dev/null 2>&1 || true

  echo "  已推送: $pushed, 已跳过: $skipped, 失败: $failed, 总计: ${#LIBS[@]}"
  if [ "$failed" -gt 0 ]; then
    echo "错误: 有 $failed 处库推送失败，请检查分区挂载/磁盘空间。" >&2
    return 1
  fi
}

# ---------- 测试推送（批量隧道） ----------
push_tests_by_type() {
  local type="$1"
  local search_base="$OUT_DIR/tests/$type"
  local device_dir="$DEVICE_TEST_BASE/${MODULE}_${type}"

  if ! [[ "$device_dir" =~ ^/data/local/tmp/[a-z0-9_.-]+_[a-z]+$ ]]; then
    echo "错误: 计算出的设备路径异常 '$device_dir'，拒绝操作" >&2
    return 1
  fi

  echo ""
  echo "=== 推送 $type 测试二进制 ==="
  win_hdc_shell "mkdir -p $device_dir" > /dev/null 2>&1

  # 1) 收集本地测试
  local -a TESTS=()
  local t
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    TESTS+=("$t")
  done < <(find "$search_base" -maxdepth 6 -type f -executable -path "*$MODULE*" \
    ! -name "*.so" ! -name "*.abc" ! -name "*.py" ! -name "*.sh" ! -name "*.txt" ! -name "*.xml" 2>/dev/null || true)
  if [ ${#TESTS[@]} -eq 0 ]; then
    echo "  未找到模块 '$MODULE' 的 $type 测试二进制。"
    echo "  搜索路径: $search_base (最大深度 6, 匹配 *$MODULE*)"
    return 0
  fi

  # 2) 设备目录现有文件 + 批量 mtime（各一次）
  local dev_ls dev_names=""
  dev_ls="$(win_hdc_shell "ls $device_dir 2>/dev/null" 2>/dev/null | tr -d '\r')"
  dev_names="$(echo "$dev_ls" | grep -v "^$" | tr '\n' ' ' || true)"
  local -A DEV_MTIME=()
  if [ "$INCREMENTAL" -eq 1 ] && [ -n "$dev_names" ]; then
    while IFS= read -r line; do
      local m p fb
      [ -z "$line" ] && continue
      m="$(awk '{print $1}' <<< "$line")"
      p="$(awk '{print $2}' <<< "$line")"
      fb="$(basename "$p")"
      DEV_MTIME["$fb"]="$m"
    done < <(win_hdc_shell "stat -c '%Y %n' $device_dir/* 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+ /')
  fi

  # 3) 增量过滤 + 陈旧清理清单
  local -a PUSH=()
  local pushed=0 skipped=0 stale=""
  local local_names=""
  for t in "${TESTS[@]}"; do local_names+=" $(basename "$t")"; done
  for t in "${TESTS[@]}"; do
    local bname local_ts dev_ts
    bname="$(basename "$t")"
    local_ts="$(stat -c '%Y' "$t" 2>/dev/null || echo 0)"
    dev_ts="${DEV_MTIME[$bname]:-0}"
    if [ "$INCREMENTAL" -eq 1 ] && [ "$dev_ts" -ge "$local_ts" ] && [ "$dev_ts" -gt 0 ]; then
      skipped=$((skipped + 1))
      continue
    fi
    PUSH+=("$t")
  done
  # 陈旧 = 设备上存在但本地没有对应文件
  local df
  for df in $dev_names; do
    grep -qw "$df" <<< "$local_names" || stale+=" '$device_dir/$df'"
  done
  [ -n "$stale" ] && win_hdc_shell "rm -f$stale" > /dev/null 2>&1 || true

  # 4) staging + 批量 file send
  if [ ${#PUSH[@]} -gt 0 ]; then
    printf '%s\n' "${PUSH[@]}" > "$LOG_DIR/push_tests.list"
    stage_pkg "$LOG_DIR/push_tests.list" || { echo "错误: staging 传输失败" >&2; return 1; }
    local hdc_cmd="\"$HDC_EXE\""
    [ -n "$TOOLCHAINS_DIR" ] && hdc_cmd="set PATH=$TOOLCHAINS_DIR;%PATH% && $hdc_cmd"
    win_ssh "cd /d $STAGE_WIN_BS && for %f in (*) do $hdc_cmd file send \"%f\" \"$device_dir/%~nxf\"" > /dev/null 2>&1 || true
    pushed=${#PUSH[@]}
  fi

  # 5) 批量校验（一次 ls 对清单）
  local dev_after count
  dev_after="$(win_hdc_shell "ls $device_dir 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -v "^$" || true)"
  count=$(echo "$dev_after" | wc -l)
  local missing=0 b2
  for b2 in $(printf '%s\n' "${PUSH[@]:-}" | xargs -r -n1 basename 2>/dev/null); do
    echo "$dev_after" | grep -qx "$b2" || { missing=$((missing + 1)); echo "  [失败] $b2 — 推送后设备上不存在！" >&2; }
  done

  # 6) chmod
  win_hdc_shell "chmod +x $device_dir/*" > /dev/null 2>&1 || true

  echo "  已推送: $pushed, 已跳过: $skipped, 已清理陈旧: $(grep -qw x <<< " $stale" && echo 0 || awk <<< "$stale" '{print NF}'), 设备目录现有 $count 个文件"
  [ "$missing" -gt 0 ] && return 1
  return 0
}

# ---------- 执行 ----------
if [ "$TESTS_ONLY" -eq 0 ]; then
  push_libs || exit 1
fi
if [ "$LIBS_ONLY" -eq 0 ]; then
  if [ "$TEST_TYPE" = "all" ]; then
    for t in unittest moduletest fuzztest benchmark; do
      push_tests_by_type "$t"
    done
  else
    push_tests_by_type "$TEST_TYPE"
  fi
fi

echo ""
echo "=== 推送完成 ==="
if [ "$TEST_TYPE" = "all" ]; then
  echo "下一步: run_module_tests.sh $MODULE --type=unittest (或其他类型)"
else
  echo "下一步: run_module_tests.sh $MODULE --type=$TEST_TYPE"
fi
