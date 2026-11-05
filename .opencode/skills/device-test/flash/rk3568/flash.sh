#!/bin/bash
# ============================================================================
# flash/rk3568/flash.sh - RK3568（Rockchip）刷机编排
#
# 架构: 服务器编排 ←隧道→ Windows 侧执行 rkdeveloptool.exe（板子接 Windows USB，Loader 模式）
#
# 数据源: out/<product>/packages/phone/images/（全套分区镜像 + parameter.txt + MiniLoaderAll.bin）
#
# 用法: flash.sh [--yes] [--help]
#   --yes   跳过交互确认（主流程 verify.sh 自动化用）
#
# 环境三查（工具/驱动/镜像）不满足时按 references/flash-env.md §1 提示准备。
# 分区地址由 flash_rk3568.bat 按同源 parameter.txt 执行（单一来源，不在本脚本重复）。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SKILL_DIR/lib/env.sh"

ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --yes)      ASSUME_YES=1 ;;
    --help|-h)  sed -n '2,18p' "$0"; exit 0 ;;
    --*)        echo "错误: 未知选项 '$arg'" >&2; exit 2 ;;
  esac
done

DOC="references/flash-env.md"

# ---------- 服务器侧数据源 ----------
OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录" >&2; exit 1; }
PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 1
IMAGES_DIR="$OH_ROOT/out/$PRODUCT/packages/phone/images"
[ -f "$IMAGES_DIR/parameter.txt" ] || { echo "错误: $IMAGES_DIR/parameter.txt 不存在（非 RK 镜像或未编译）" >&2; exit 1; }
echo "产品: $PRODUCT    镜像: $IMAGES_DIR"
echo ""

# ---------- Windows 侧环境三查 ----------
RKT_EXE_WIN=""
flash_env_check() {
    local missing=0
    if RKT_EXE_WIN="$(flash_find_tool_win rkdeveloptool.exe)"; then
        # 工具旁须有 libusb-1.0.dll（rkdeveloptool 的 USB 后端）
        local rkt_dir
        rkt_dir="$(dirname "$RKT_EXE_WIN")"
        if win_ssh "if not exist \"$rkt_dir\\libusb-1.0.dll\" exit /b 1" > /dev/null 2>&1; then
            echo "[环境OK] 工具: $RKT_EXE_WIN"
        else
            echo "[缺依赖] $RKT_EXE_WIN 旁无 libusb-1.0.dll" >&2
            missing=1
        fi
    else
        echo "[缺工具] Windows 侧未找到 rkdeveloptool.exe（已探测: env.conf 登记位置 → \$WIN_DIR\\bin → PATH → 用户目录扫描）" >&2
        missing=1
    fi
    if flash_check_driver_win 2207; then
        echo "[环境OK] 驱动: VID_2207(Rockchip) WinUSB 已安装"
    else
        echo "[缺驱动] Windows 侧无 VID_2207 WinUSB 驱动（Loader 设备默认绑 Rockusb 私有驱动，libusb 打不开）" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        echo "" >&2
        echo "环境准备步骤详见 $DOC（§0 通用 + §1 RK3568）:" >&2
        echo "  1. 服务器执行: bash $SKILL_DIR/bin/ensure_bin.sh                （构建 rkdeveloptool.exe/libusb/wdi-simple）" >&2
        echo "  2. 部署: bin/ 内容拷到 Windows \$WIN_DIR\\bin\\（scp 命令见 §0）" >&2
        echo "  3. 驱动: Windows 管理员执行 install_winusb.bat（wdi-simple 全自动，见 §1）" >&2
        echo "  4. 重新执行本命令" >&2
        return 1
    fi
    return 0
}
flash_env_check || exit 1
echo ""

# ---------- 交互确认 ----------
if [ "$ASSUME_YES" -ne 1 ]; then
  echo "!!! 刷机是毁灭性操作（RK3568 全分区）!!!"
  read -rp "确认继续请输入 yes: " ACK
  [ "$ACK" = "yes" ] || { echo "已取消。"; exit 1; }
fi

# ---------- 镜像传输（tar 打包，排除 eng_system.img 超大调试镜像） ----------
STAGE_WIN="$WIN_DIR/flash/rk3568"
STAGE_WIN_BS="$WIN_DIR_BS\\flash\\rk3568"
echo "==== 传输镜像到 Windows: $STAGE_WIN\\images （排除 eng_system.img）===="
tar czf "$LOG_DIR/rk3568_images.tar.gz" -C "$IMAGES_DIR" --exclude=eng_system.img . || exit 1
win_ssh "(if not exist $STAGE_WIN_BS mkdir $STAGE_WIN_BS)" || exit 1
$SCP_CMD "$LOG_DIR/rk3568_images.tar.gz" "$WIN_USER@127.0.0.1:$WIN_TMP/" || exit 1
win_ssh "cd /d $STAGE_WIN_BS && if not exist images mkdir images && tar xzf $WIN_DIR_BS\\tmp\\rk3568_images.tar.gz -C images && del $WIN_DIR_BS\\tmp\\rk3568_images.tar.gz" || exit 1
echo "镜像就位: $STAGE_WIN_BS\\images"
echo ""

# ---------- 进入 Loader 模式 ----------
echo "==== 进入 Loader 模式 ===="
if win_hdc list targets 2>/dev/null | grep -qv "Empty"; then
  echo "设备在线，软进 Loader: reboot loader"
  win_hdc shell "reboot loader" > /dev/null 2>&1 || true
  sleep 5
else
  echo "设备不在线（可能已关机）——请物理进入 Loader: 按住 RECOVERY 再按 RESET"
fi
echo ""

# ---------- 执行刷机（Windows 侧 flash_rk3568.bat，分区地址以 parameter.txt 为准） ----------
echo "==== 执行刷机 ===="
$SCP_CMD "$SCRIPT_DIR/flash_rk3568.bat" "$WIN_USER@127.0.0.1:$STAGE_WIN/flash_rk3568.bat" || exit 1
win_ssh "cd /d $STAGE_WIN_BS && flash_rk3568.bat $STAGE_WIN_BS\\images $RKT_EXE_WIN" || { echo "[ERROR] 刷机失败（Loader 设备未出现时检查进模方式）" >&2; exit 1; }
echo ""

# ---------- 等待设备回来 ----------
echo "==== 等待设备重启回来（经隧道 hdc 轮询）===="
for i in $(seq 1 24); do
  if win_hdc list targets 2>/dev/null | grep -qv "Empty"; then
    echo "[OK] 设备已回来（第 $((i*5)) 秒）"
    echo "后续: test/check_sync.sh 复验同步状态，然后跑测试"
    exit 0
  fi
  sleep 5
done
echo "[WARN] 120 秒内未见设备回来——请检查板子" >&2
exit 1
