#!/bin/bash
# ============================================================================
# common.sh - 链路 B 工作流层（Windows 隧道侧；被 tunnel 各脚本 source）
# 提供: 工作区/交付框架定位 / 板子检查(经隧道) / 环境自检 / 报告回收与解析
# 环境层(配置/隧道/探测)统一在 lib/env.sh
# ============================================================================
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$SKILL_DIR/lib/env.sh"

# ---------- 工作区自动探测 ----------
CODE_DIR="$(dt_resolve_oh_root)"
if [ -z "${CODE_DIR:-}" ]; then
    echo "[ERROR] 找不到 OpenHarmony 源码目录(需在 code/ 内或其子目录执行)" >&2
    exit 1
fi
WS_ROOT="$(dirname "$CODE_DIR")"
DELIVERY="${DELIVERY_DIR:-}"
if [ -z "$DELIVERY" ]; then
    if [ -d "$WS_ROOT/rk3568_delivery" ]; then DELIVERY="$WS_ROOT/rk3568_delivery"   # 兼容旧名
    else DELIVERY="$WS_ROOT/board-test_delivery"; fi
fi
if [ ! -d "$DELIVERY/Test/developer_test" ]; then
    # 交付框架缺失：直接从源码树构建（developer_test + xdevice）
    echo "[INIT] 交付框架缺失，从源码树构建..."
    mkdir -p "$DELIVERY/Test"
    cp -r "$CODE_DIR/test/testfwk/developer_test" "$DELIVERY/Test/" || { echo "[ERROR] 拷贝 developer_test 失败"; exit 1; }
    cp -r "$CODE_DIR/test/testfwk/xdevice" "$DELIVERY/Test/" || { echo "[ERROR] 拷贝 xdevice 失败"; exit 1; }
fi
mkdir -p "$LOG_DIR" "$DELIVERY/reports"

# ---------- 产品名探测（板级产品特征: packages/phone/images，排除 sdk 等非板级构建） ----------
PRODUCT_NAME="${PRODUCT_NAME:-}"
if [ -z "$PRODUCT_NAME" ]; then
    for d in "$CODE_DIR"/out/*/; do
        if [ -d "${d}packages/phone/images" ]; then
            PRODUCT_NAME="$(basename "$d")"; break
        fi
    done
fi
if [ -z "$PRODUCT_NAME" ]; then
    echo "[ERROR] 无法识别产品名(out/ 下无板级产品)。请在 $CONF_FILE 中设置 PRODUCT_NAME" >&2
    exit 1
fi

# ---------- 通用检查 ----------
check_board() {
    local out
    out=$(win_hdc list targets 2>/dev/null | grep -v "Empty" | head -1)
    if [ -n "$out" ]; then echo "[OK] 板子: $out"; return 0; fi
    echo "[ERROR] hdc 未发现设备，检查板子 USB(OTG口)/上电/系统启动" >&2
    return 1
}
run_env_check() {
    echo "=== 测试环境自检（链路 B: 经隧道）==="
    echo "源码目录: $CODE_DIR"
    echo "交付目录: $DELIVERY"
    check_tunnel || return 1
    echo "[OK] 隧道"
    check_board || return 1
    local py
    py=$(win_ssh "\"$PYTHON_EXE\" --version" 2>/dev/null)
    echo "[OK] Windows Python: $py"
    local pyver
    pyver="$(echo "$py" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
    case "$pyver" in
        3.8|3.9|"") : ;;
        *) echo "[WARN] Python $pyver 可能不兼容 ACTS/TDD 路径（团队验证版本为 3.8）；"
           echo "       如需使用先把 $CONF_FILE 中 PYTHON_EXE 指向 python3.8" ;;
    esac
    echo "=== 全部通过 ==="
}

# ---------- 报告回收与解析 ----------
collect_report() {
    local kind="$1"   # tdd | acts
    local zip
    if [ "$kind" = "acts" ]; then
        win_ssh 'powershell -c "Compress-Archive -Path '"$WIN_DIR_BS"'\acts\reports -DestinationPath '"$WIN_DIR_BS"'\reports\acts_reports.zip -Force"'
        zip="acts_reports.zip"
    else
        local latest
        latest=$(win_ssh 'dir /b /o-d '"$WIN_DIR_BS"'\reports\tdd_reports_*.zip 2>nul' | head -1 | tr -d '\r')
        [ -z "$latest" ] && { echo "[WARN] 无 TDD 报告"; return 1; }
        zip="$latest"
    fi
    mkdir -p "$DELIVERY/reports/$kind"
    $SCP_CMD "$WIN_USER@127.0.0.1:$WIN_DIR/reports/$zip" "$DELIVERY/reports/$kind/" || return 1
    local stamp=$(date +%Y%m%d_%H%M%S)
    unzip -qo "$DELIVERY/reports/$kind/$zip" -d "$DELIVERY/reports/$kind/run_$stamp" 2>/dev/null
    echo ""
    echo "================= $kind 测试结果 ================="
    find "$DELIVERY/reports/$kind/run_$stamp" -name summary.ini 2>/dev/null -exec cat {} \;
    echo "---------------------------------------------------"
    python3 - "$DELIVERY/reports/$kind/run_$stamp" <<'EOF'
import sys, os, xml.etree.ElementTree as ET
root = sys.argv[1]
for dirpath, _, files in os.walk(root):
    if 'summary_report.xml' in files:
        try:
            tree = ET.parse(os.path.join(dirpath, 'summary_report.xml'))
        except Exception:
            continue
        for node in tree.iter():
            if node.tag.split('}')[-1] in ('suite', 'test') and node.get('result') in ('false', 'Failure', 'failed'):
                print("[FAIL]", node.get('name'), '-', node.get('message', '')[:120])
        break
print("解析目录:", root)
EOF
    echo "==================================================="
    echo "HTML 报告: $DELIVERY/reports/$kind/run_$stamp/ 下 summary_report.html"
}
