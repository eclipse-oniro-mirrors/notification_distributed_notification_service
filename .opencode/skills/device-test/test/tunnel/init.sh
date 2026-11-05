#!/bin/bash
# ============================================================================
# init.sh - 同事初始化向导：密钥/个人配置/个性化 Windows 安装脚本
# 用法: init.sh [win_user] [server_ip] [server_port]
#   三参齐备则跳过交互；否则逐步询问
# ============================================================================
source "$(dirname "$0")/common.sh"

write_conf() {
    mkdir -p "$(dirname "$CONF_FILE")"
    cat > "$CONF_FILE" <<EOF
# ohos-board-test 个性化配置（init 向导生成，可手改）
WIN_USER="$WIN_USER"
WIN_DIR="$WIN_DIR"
HDC_EXE="$HDC_EXE"
TOOLCHAINS_DIR="$TOOLCHAINS_DIR"
PYTHON_EXE="$PYTHON_EXE"
PRODUCT_NAME="${PRODUCT_NAME:-}"
EOF
    echo "[INIT] 配置已写入 $CONF_FILE"
}
render_setup_ps1() {  # $1=ip $2=port $3=server_user
    sed -e "s|__SERVER_IP__|$1|g" -e "s|__SERVER_PORT__|$2|g" \
        -e "s|__SERVER_USER__|$3|g" -e "s|__PUBKEY__|$(cat $KEY.pub)|g" \
        "$SKILL_DIR/test/tunnel/templates/setup_win_once.ps1.tmpl" > "$DELIVERY/setup_win_once.ps1"
}
probe_hdc() {
    local found
    found=$(win_ssh "where /R C:\\Users\\$WIN_USER\\AppData\\Local\\OpenHarmony hdc.exe 2>nul" 2>/dev/null | head -1 | tr -d '\r')
    if [ -n "$found" ]; then
        HDC_EXE="$found"
        TOOLCHAINS_DIR="$(echo "$found" | sed 's|\\hdc.exe||')"
        return 0
    fi
    return 1
}

echo "=== RK3568 测试闭环 初始化向导 ==="
[ -f "$CONF_FILE" ] && echo "[INIT] 已存在配置 $CONF_FILE（重新 init 会覆盖）"

# ---------- 收集信息 ----------
if [ $# -ge 3 ]; then
    WIN_USER="$1"; SERVER_IP="$2"; SERVER_PORT="$3"
else
    read -rp "你的 Windows 用户名: " WIN_USER
    while [ -z "$WIN_USER" ]; do read -rp "Windows 用户名不能为空，请重新输入: " WIN_USER; done
    read -rp "服务器入口 IP (你 VS Code ssh config 里的 HostName): " SERVER_IP
    while [ -z "$SERVER_IP" ]; do read -rp "服务器入口 IP 不能为空，请重新输入: " SERVER_IP; done
    read -rp "服务器入口端口 (ssh config 里的 Port): " SERVER_PORT
    while [ -z "$SERVER_PORT" ]; do read -rp "服务器入口端口不能为空，请重新输入: " SERVER_PORT; done
fi
read -rp "服务器 SSH 用户名 [${USER:-$(id -un)}]: " SERVER_USER; SERVER_USER="${SERVER_USER:-${USER:-$(id -un)}}"
read -rp "Windows Python 路径 [python=用PATH里的]: " PYTHON_EXE; PYTHON_EXE="${PYTHON_EXE:-python}"
WIN_DIR="C:/Users/$WIN_USER/board-test"
HDC_EXE="hdc"; TOOLCHAINS_DIR=""

# ---------- 密钥 ----------
if [ ! -f "$KEY" ]; then
    ssh-keygen -t ed25519 -f "$KEY" -N "" -q && echo "[INIT] 已生成密钥对 $KEY"
else
    echo "[INIT] 复用已有密钥 $KEY"
fi

# ---------- 写配置 + 渲染安装脚本 ----------
write_conf
render_setup_ps1 "$SERVER_IP" "$SERVER_PORT" "$SERVER_USER"
> /tmp/opencode/tunnel_status.txt; chmod 666 /tmp/opencode/tunnel_status.txt 2>/dev/null

cat <<EOF

[INIT] 完成。现在到你的 Windows 上执行（管理员 PowerShell）：

  scp -P $SERVER_PORT $SERVER_USER@$SERVER_IP:$DELIVERY/setup_win_once.ps1 \$env:TEMP\\setup_win_once.ps1; powershell -ExecutionPolicy Bypass -File \$env:TEMP\\setup_win_once.ps1

它会: 装 OpenSSH Server -> 装入服务器公钥 -> 建隧道(桌面+开机自启)。
隧道窗口输入服务器密码后，回到这里按回车继续（或 Ctrl+C 退出，之后随时跑 check.sh）。
EOF
read -rp ">>> 隧道建好了按回车继续探测环境..."
check_tunnel || exit 1

# ---------- 探测同事机器上的 hdc/python ----------
if probe_hdc; then
    echo "[INIT] 探测到 hdc: $HDC_EXE"
else
    echo "[INIT] 未在 %LOCALAPPDATA%\\OpenHarmony 下找到 hdc，保持 PATH 查找(确认 hdc 已装并加入 PATH)"
fi

# ---------- 沿用已部署目录（团队既有 Windows 机已在 rk3568\ 下部署框架/报告） ----------
# 判定: 候选目录下存在 acts/Test/bin/flash/tmp 任一即视为"已部署工作目录"，
#       避免把 staging 落到空目录后 ACTS/TDD 框架找不到（首次使用常见坑）
probe_deployed_dir() {
    local cand sub
    for cand in rk3568 board-test; do
        for sub in acts Test bin flash; do
            if win_ssh "if exist C:\\Users\\$WIN_USER\\$cand\\$sub (exit /b 0) else (exit /b 1)" > /dev/null 2>&1; then
                echo "C:/Users/$WIN_USER/$cand"
                return 0
            fi
        done
    done
    return 1
}
if d="$(probe_deployed_dir)"; then
    if [ "$d" != "$WIN_DIR" ]; then
        echo "[INIT] 检测到已部署目录 ${d//\//\\}（含已部署框架/工具），WIN_DIR 沿用它"
        WIN_DIR="$d"
    fi
fi
write_conf
echo ""
# ---------- 自动登记展锐刷机工具（wukong100 全自动刷机必需） ----------
if tool="$(flash_find_tool_win CmdDloader.exe 2>/dev/null)" && [ -n "$tool" ]; then
    tool_dir="${tool%\\*}"
    if ! grep -q '^FLASH_TOOL_DIR=' "$CONF_FILE" 2>/dev/null; then
        echo "FLASH_TOOL_DIR=\"${tool_dir//\\//}\"" >> "$CONF_FILE"
    fi
    echo "[INIT] 已登记刷机工具目录: $tool_dir"
else
    echo "[INIT] 未发现 CmdDloader.exe（wukong100 刷机需要）：解压展锐 ResearchDownload 工具包后重跑 init，"
    echo "       或在 $CONF_FILE 中登记 FLASH_TOOL_DIR=<含 CmdDloader.exe 的目录>"
fi
run_env_check
echo ""
echo "[INIT] 全部就绪。日常用法:"
echo "  $(dirname "$0")/run_tdd.sh <部件名> [测试目标]   # TDD"
echo "  $(dirname "$0")/run_acts.sh <部件名> [模块名]    # ACTS"
echo "  $(dirname "$0")/push_so.sh <部件名>              # 增量推 so"
