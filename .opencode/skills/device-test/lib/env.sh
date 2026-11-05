#!/bin/bash
# ============================================================================
# lib/env.sh - device-test 唯一环境层（被所有功能脚本 source，不直接执行）
#
# 提供:
#   个人配置(env.conf)加载与自动推导 / 隧道访问封装(win_ssh/win_hdc) /
#   OH 根目录与产品探测 / 直连 hdc 定位与设备探活 / 设备探测(架构/库目录/md5) /
#   链路自适应设备访问 / Windows 侧刷机程序动态发现与驱动检查
#
# 配置优先级: 环境变量 > env.conf(init 向导生成) > 自动探测/推导
# ============================================================================

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------- 个人配置加载（env.conf，init 向导生成） ----------
CONF_FILE="${BOARD_TEST_CONF:-$HOME/.config/ohos-board-test/env.conf}"
# 兼容旧版配置(rk3568-test 时代)
if [ ! -f "$CONF_FILE" ] && [ -f "$HOME/.config/rk3568-test/env.conf" ]; then
    mkdir -p "$(dirname "$CONF_FILE")"; cp "$HOME/.config/rk3568-test/env.conf" "$CONF_FILE"
fi
[ -f "$CONF_FILE" ] && source "$CONF_FILE"

# ---------- WIN_USER 自动推导（仅当 env.conf/环境变量为空时） ----------
# 隧道 bat 每次连接都向 /tmp/opencode/tunnel_status.txt 写入 "TUNNEL_UP <Windows用户名>"，
# 取最后一条记录即当前实际建立隧道的 Windows 用户——是实时推导而非硬编码默认值。
if [ -z "${WIN_USER:-}" ] && [ -f /tmp/opencode/tunnel_status.txt ]; then
    WIN_USER="$(tr -d '\r' < /tmp/opencode/tunnel_status.txt | awk '/^TUNNEL_UP /{u=$2} END{if(u)print u}')"
    [ -n "$WIN_USER" ] && echo "[CONF] WIN_USER 未配置，已从隧道连接记录推导: $WIN_USER（可用 init.sh 固化）"
fi

# ---------- 常量（env.conf 可覆盖） ----------
TUNNEL_PORT="${TUNNEL_PORT:-12222}"
# WIN_DIR 校验: 空值或与已解析的 WIN_USER 不一致（如历史配置中空用户名写入的
# "C:/Users//board-test"）时，按 WIN_USER 重算，避免 scp 到不存在的路径
if [ -z "${WIN_DIR:-}" ] || ! grep -q "${WIN_USER:-__none__}" <<< "${WIN_DIR:-}"; then
    WIN_DIR="C:/Users/${WIN_USER:-}/board-test"
fi
WIN_TMP="$WIN_DIR/tmp"
WIN_DIR_BS="$(echo "$WIN_DIR" | tr '/' '\\')"
HDC_EXE="${HDC_EXE:-hdc}"
PYTHON_EXE="${PYTHON_EXE:-python}"
TOOLCHAINS_DIR="${TOOLCHAINS_DIR:-}"
if [ -n "${KEY:-}" ]; then :
elif [ -f "$HOME/.ssh/board_win" ]; then KEY="$HOME/.ssh/board_win"
elif [ -f "$HOME/.ssh/rk3568_win" ]; then KEY="$HOME/.ssh/rk3568_win"   # 兼容旧名
else KEY="$HOME/.ssh/board_win"; fi
SSH_CMD="ssh -p $TUNNEL_PORT -i $KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
SCP_CMD="scp -q -P $TUNNEL_PORT -i $KEY -o StrictHostKeyChecking=no"
LOG_DIR="/tmp/opencode"

# ---------- 隧道访问封装 ----------
win_ssh() { $SSH_CMD "$WIN_USER@127.0.0.1" "$@"; }

# Windows 侧 hdc 执行（板子接 Windows 时，经隧道调用 hdc）
# 注意: 仅用于非 shell 子命令(list/file send/target mount 等)
win_hdc() {
    local path_prefix=""
    [ -n "$TOOLCHAINS_DIR" ] && path_prefix="set PATH=$TOOLCHAINS_DIR;%PATH% && "
    win_ssh "$path_prefix$HDC_EXE $*"
}

# Windows 侧 hdc shell——设备命令整体加引号包裹:
# cmd 不解析引号内的重定向符(2>/dev/null)与 &&（否则会被 cmd 截获导致命令中止）。
# 因此设备命令内勿再用双引号（路径无空格时裸写或用单引号）。
win_hdc_shell() {
    local path_prefix=""
    [ -n "$TOOLCHAINS_DIR" ] && path_prefix="set PATH=$TOOLCHAINS_DIR;%PATH% && "
    win_ssh "$path_prefix\"$HDC_EXE\" shell \"$*\""
}

# 带超时的 win_hdc_shell（timeout 无法包装函数，此处展开 ssh 命令）
win_hdc_timeout() {
    local secs="$1"; shift
    local path_prefix=""
    [ -n "$TOOLCHAINS_DIR" ] && path_prefix="set PATH=$TOOLCHAINS_DIR;%PATH% && "
    timeout "$secs" $SSH_CMD "$WIN_USER@127.0.0.1" "$path_prefix\"$HDC_EXE\" shell \"$*\""
}

# 配置校验: 功能脚本执行前调用，确保 WIN_USER 已配置。
# 注意: init.sh 在向导收集前 source 本文件，故不在 source 时强制。
require_config() {
    if [ -z "${WIN_USER:-}" ]; then
        echo "[ERROR] 未配置 WIN_USER。请先执行一次初始化向导: $SKILL_DIR/test/tunnel/init.sh" >&2
        echo "         （生成 $CONF_FILE；也可通过环境变量/已有配置文件提供）" >&2
        return 1
    fi
    return 0
}

check_tunnel() {
    timeout 3 bash -c "</dev/tcp/127.0.0.1/$TUNNEL_PORT" 2>/dev/null && return 0
    echo "[ERROR] 反向隧道不通。请在 Windows 桌面双击隧道脚本(board_tunnel.bat，旧部署为 rk3568_tunnel.bat)并输入服务器密码后重试" >&2
    return 1
}

# ---------- OH 根目录与产品探测 ----------
# 定位 OpenHarmony 根目录（向上查找 .gn 或 build.sh；OH_ROOT 环境变量优先）
dt_resolve_oh_root() {
    local root="${OH_ROOT:-}"
    if [ -n "$root" ]; then echo "$root"; return 0; fi
    local d="$PWD"
    while [ "$d" != "/" ]; do
        if [ -f "$d/.gn" ] || [ -f "$d/build.sh" ]; then echo "$d"; return 0; fi
        d="$(dirname "$d")"
    done
    return 1
}

# 产品个人配置(env.conf 的 PRODUCT_NAME，与链路 B 共用)
dt_conf_product() {
    [ -f "$CONF_FILE" ] || return 1
    local v
    v="$(sed -n 's/^PRODUCT_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$CONF_FILE" | head -1)"
    [ -n "$v" ] || return 1
    echo "$v"
}

# 自动探测产品名。优先级: OH_PRODUCT 环境变量 > env.conf PRODUCT_NAME
# > 自动探测（out/ 下含 packages/phone/images 的板级产品；排除 sdk 等非板级构建）
# 多个板级产品并存且未配置时报错列出候选（避免静默用错产品）
dt_detect_product() {
    local oh_root="$1"
    if [ -n "${OH_PRODUCT:-}" ]; then echo "$OH_PRODUCT"; return 0; fi
    local conf_p
    conf_p="$(dt_conf_product 2>/dev/null)" || conf_p=""
    if [ -n "$conf_p" ]; then echo "$conf_p"; return 0; fi
    local found=()
    local d
    for d in "$oh_root"/out/*/; do
        [ -f "${d}args.gn" ] && [ -d "${d}packages/phone/images" ] && found+=("$(basename "$d")")
    done
    case ${#found[@]} in
        0) echo "错误: $oh_root/out/ 下无板级产品（需含 packages/phone/images 的已编译产品）。请先编译，或设置 OH_PRODUCT。" >&2; return 1 ;;
        1) echo "${found[0]}"; return 0 ;;
        *) echo "错误: 检测到多个板级产品(${found[*]})，请设置 OH_PRODUCT 或在 env.conf 配置 PRODUCT_NAME 指定其一。" >&2; return 1 ;;
    esac
}

# ---------- 设备访问（唯一链路：经隧道 Windows hdc——服务器不连接设备） ----------
# 设备探活: Windows 侧 hdc 可见设备且 shell 可用（区分 无设备/offline/unauthorized）
dt_probe_device() {
    local targets probe
    targets="$(win_hdc list targets 2>/dev/null | tr -d '\r')"
    if [ -z "$targets" ] || grep -q "Empty" <<< "$targets"; then
        echo "错误: Windows 侧 hdc 未发现设备。检查: 板子接 Windows USB、上电、系统启动" >&2
        return 1
    fi
    probe="$(win_hdc_shell "echo ok" 2>/dev/null | tr -d '\r')"
    if [ "$probe" != "ok" ]; then
        echo "错误: 设备已连接但不可用 (可能 offline/unauthorized)。Windows 侧检查: $HDC_EXE list targets" >&2
        return 1
    fi
    return 0
}

# 设备端 shell（经隧道 Windows hdc）
dt_device_shell() { win_hdc_shell "$@"; }

# 设备架构 → 系统库目录名（aarch64/64位 → lib64，其余 → lib）
dt_device_arch_libdir() {
    local arch
    arch="$(win_hdc_shell "uname -m" 2>/dev/null | tr -d '\r' | head -1)"
    case "$arch" in
        aarch64|x86_64) echo "lib64" ;;
        *)              echo "lib" ;;
    esac
}

# 设备端存在的模块库目录（供 LD_LIBRARY_PATH / 新库落位使用）
# 返回冒号分隔列表（按优先级）: $LIBDIR/platformsdk:$LIBDIR（仅列实际存在的）
dt_device_lib_dirs() {
    local archlib="/system/$(dt_device_arch_libdir)"
    local -a dirs=()
    if [ "$(win_hdc_shell "[ -d '$archlib/platformsdk' ] && echo DT_DIR_YES" 2>/dev/null | tr -d '\r' | grep -cx DT_DIR_YES)" = "1" ]; then
        dirs+=("$archlib/platformsdk")
    fi
    if [ "$(win_hdc_shell "[ -d '$archlib' ] && echo DT_DIR_YES" 2>/dev/null | tr -d '\r' | grep -cx DT_DIR_YES)" = "1" ]; then
        dirs+=("$archlib")
    fi
    if [ ${#dirs[@]} -eq 0 ]; then
        dirs=("/system/lib/platformsdk" "/system/lib")   # 兜底（老 32 位设备）
    fi
    local IFS=:
    echo "${dirs[*]}"
}

# 设备端按文件名探测库的实际路径（可多处命中，逐行返回；未命中返回空）
dt_find_lib_on_device() {
    win_hdc_shell "find /system /vendor /sys_prod /chip_prod -name '$1' 2>/dev/null" 2>/dev/null \
        | tr -d '\r' | grep -v "^$" | grep -v "find:" | sort -u
}

# 设备端 md5（失败返回空）
dt_md5_device() {
    win_hdc_shell "md5sum '$1' 2>/dev/null" 2>/dev/null | tr -d '\r' | awk '{print $1}'
}

# 设备端文件存在性检查（可靠判定，不依赖 exit code / 不匹配错误文本）
dt_file_exists_on_device() {
    [ "$(win_hdc_shell "[ -f '$1' ] && echo DT_EXISTS" 2>/dev/null | tr -d '\r' | grep -cx DT_EXISTS)" = "1" ]
}

# 设备端文件 mtime（epoch 秒；失败返回 0）——增量判定用
dt_stat_mtime_device() {
    local ts
    ts="$(win_hdc_shell "stat -c '%Y' '$1' 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+$' | head -1)"
    echo "${ts:-0}"
}

# 设备端批量 mtime（一次隧道往返取多文件; 输出 "mtime path" 行）
dt_stat_mtimes_device() {
    win_hdc_shell "stat -c '%Y %n' $* 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -E '^[0-9]+ /'
}

# ---------- Windows 侧刷机程序动态发现与驱动检查（刷机域共用） ----------
# 动态发现探测链: env.conf 登记(FLASH_TOOL_DIR) → 约定目录($WIN_DIR/bin) → PATH → 用户目录扫描(慢,兜底)
# 成功输出 Windows 侧 exe 路径；失败返回 1（调用方负责按文档指引提示）
flash_find_tool_win() {
    local exe="$1" found=""
    require_config > /dev/null 2>&1 || return 1
    check_tunnel > /dev/null 2>&1 || return 1
    # 1. env.conf 登记
    if [ -n "${FLASH_TOOL_DIR:-}" ]; then
        found=$(win_ssh "if exist \"${FLASH_TOOL_DIR//\//\\}\\$exe\" echo ${FLASH_TOOL_DIR//\//\\}\\$exe" 2>/dev/null | tr -d '\r' | head -1)
        [ -n "$found" ] && { echo "$found"; return 0; }
    fi
    # 2. 约定目录
    found=$(win_ssh "if exist \"$WIN_DIR_BS\\bin\\$exe\" echo $WIN_DIR_BS\\bin\\$exe" 2>/dev/null | tr -d '\r' | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    # 3. PATH
    found=$(win_ssh "where $exe 2>nul" 2>/dev/null | tr -d '\r' | head -1)
    case "$found" in *"$exe"*) echo "$found"; return 0 ;; esac
    # 4. 常见目录快速扫描(限时 20s): Desktop/Downloads/WIN_DIR 根。
    #    全用户目录扫描太慢(>60s)不在此做——自定义位置请在 env.conf 登记 FLASH_TOOL_DIR
    found=$(timeout 20 $SSH_CMD "$WIN_USER@127.0.0.1" \
        "where /R C:\\Users\\$WIN_USER\\Desktop $exe 2>nul & where /R C:\\Users\\$WIN_USER\\Downloads $exe 2>nul & where /R \"$WIN_DIR_BS\" $exe 2>nul" \
        2>/dev/null | tr -d '\r' | grep -a "$exe" | grep -av "INFO:" | head -1)
    case "$found" in *"$exe"*) echo "$found"; return 0 ;; esac
    # 4b. 展锐工具包专项(CmdDloader/ResearchDownload): 数据盘根下两级 + Program Files
    #     例: D:\DAYU600-Flash-Tools\SPD_Research_Tool_R25.21.1401\CmdDloader.exe
    case "$exe" in
      CmdDloader.exe|ResearchDownload.exe)
        local root
        for root in "D:" "E:" "F:" "C:\\Program Files" "C:\\Program Files (x86)" "C:\\Users\\$WIN_USER"; do
            found=$(timeout 30 $SSH_CMD "$WIN_USER@127.0.0.1" \
                "powershell -NoProfile -Command \"Get-ChildItem -Path '$root\\' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem \$_.FullName -Directory -ErrorAction SilentlyContinue } | Where-Object { Test-Path (Join-Path \$_.FullName '$exe') } | Select-Object -First 1 -ExpandProperty FullName\"" \
                2>/dev/null | tr -d '\r' | grep -aE '^[A-Za-z]:\\' | head -1)
            if [ -n "$found" ]; then
                echo "${found}\\$exe"
                return 0
            fi
        done
        ;;
    esac
    return 1
}

# Windows 侧驱动检查: 驱动库 INF 内容中查找指定 USB VID（如 2207=Rockchip / 1782=SPRD）
# 注: pnputil /enum-drivers 的输出不含硬件 ID(VID)，须查驱动库 INF 文件内容
flash_check_driver_win() {
    require_config > /dev/null 2>&1 || return 1
    check_tunnel > /dev/null 2>&1 || return 1
    win_ssh "findstr /m /i \"VID_$1\" C:\\Windows\\INF\\oem*.inf" 2>/dev/null | tr -d '\r' | grep -q "\.inf"
}
