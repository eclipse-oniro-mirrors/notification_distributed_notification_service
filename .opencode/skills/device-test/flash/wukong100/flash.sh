#!/bin/bash
# ============================================================================
# flash/wukong100/flash.sh - wukong100（Unisoc UIS7885/UMS9620）刷机编排
#
# 架构: 服务器解析与编排 ←隧道→ Windows 侧执行刷机程序（板子接 Windows USB）
#       工具: CmdDloader.exe（官方 PAC，默认）/ spd_dump.exe（分区镜像）
#
# 数据源（零额外资产，全部来自构建产物与源码树）:
#   分区镜像:   out/<product>/packages/phone/images/*.img
#   FDL/角色映射: device/soc/unisoc/p7885/pac/ImageFiles/
#                （flash.cfg=本次构建实际打包条目 + SoC XML=权威映射与FDL地址）
#
# 用法: flash.sh [--dry-run] [--include-nv] [--spl=emmc|ufs] [--skip=<角色,...>]
#                [--tool=auto|cmdloader|spd_dump] [--wait=<秒>] [--yes] [--check-env] [--bootstrap] [--help]
#   --dry-run   只打印操作计划与将执行的命令，不传输不刷机
#   --tool=     刷机工具路线。auto(默认)=有官方 PAC 用 CmdDloader，否则 spd_dump；
#               cmdloader=官方 PAC 全自动（软件进下载模式+刷完自动复位）；
#               spd_dump=按分区镜像逐个写入（需设备绑定 WinUSB 驱动）
#   --include-nv 额外写 prodnv 分区（默认跳过！见下）
#   --spl=      SPL 变体（emmc|ufs）。官方 pac 携带两个变体、刷时按实际存储二选一；
#               板子运行中时自动探测（/sys/block），探测不到必须显式指定或交互确认
#   --skip=     跳过指定角色（逗号分隔）
#   --yes       跳过交互确认（主流程 verify.sh 自动化用）
#   --check-env 只做刷机环境自检（隧道/设备/工具/驱动/PAC），缺项时打印首次准备引导
#   --bootstrap 一键构建并部署仓库自带刷机工具（spd_dump/libusb/wdi-simple），无需厂商包
#
# 安全设计:
#   - prodnv（生产 NV，含校准/许可数据）默认不写：保留板上既有 NV，
#     避免官方工具 NvBackup 编排无法复刻导致的 NV 损坏风险；确需重置才 --include-nv
#   - 刷机是毁灭性操作：镜像必须与目标板配套（同工作区产物）
#   - 环境三查（工具/驱动/镜像）不满足时按 references/flash-env.md §2 提示准备
#
# 进入下载模式: ①软件(系统在线首选): hdc shell reboot autodloader（拼写必须为 autodloader）
#              ②物理: 按住三按键一侧中间键 音量+(VOL+) 接 USB/上电
#                （注意: 下载模式下设备绑定展锐 U2S 串口驱动, spd_dump(libusb) 打不开,
#                  默认路线改用官方 CmdDloader.exe -pac <pac> 走 COM 口，并由
#                  ResearchDownload.ini [Options] Reset=1 在刷完后自动复位）
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SKILL_DIR/lib/env.sh"

DRY_RUN=0
INCLUDE_NV=0
SKIP_ROLES=""
SPL_VARIANT=""
WAIT_SECS=300
ASSUME_YES=0
TOOL_MODE="auto"        # auto | cmdloader | spd_dump
CHECK_ENV=0             # --check-env: 只做环境自检并给出首次准备引导
BOOTSTRAP=0             # --bootstrap: 构建并部署仓库自带刷机工具（无需厂商包）

for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY_RUN=1 ;;
    --include-nv)   INCLUDE_NV=1 ;;
    --skip=*)       SKIP_ROLES="${arg#--skip=}" ;;
    --spl=*)        SPL_VARIANT="${arg#--spl=}" ;;
    --wait=*)       WAIT_SECS="${arg#--wait=}" ;;
    --tool=*)       TOOL_MODE="${arg#--tool=}" ;;
    --check-env)    CHECK_ENV=1 ;;
    --bootstrap)    BOOTSTRAP=1 ;;
    --yes)          ASSUME_YES=1 ;;
    --help|-h)      sed -n '2,37p' "$0"; exit 0 ;;
    --*)            echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
  esac
done

DOC="references/flash-env.md"

# ---------- 服务器侧数据源 ----------
OH_ROOT="$(dt_resolve_oh_root)" || { echo "错误: 无法定位 OpenHarmony 根目录（在源码树内运行或设 OH_ROOT）" >&2; exit 1; }
PRODUCT="$(dt_detect_product "$OH_ROOT")" || exit 1
IMAGES_DIR="$OH_ROOT/out/$PRODUCT/packages/phone/images"
[ -d "$IMAGES_DIR" ] || { echo "错误: $IMAGES_DIR 不存在" >&2; exit 1; }

IMAGEFILES="$(find "$OH_ROOT/device/soc/unisoc" -maxdepth 4 -name flash.cfg -exec dirname {} \; 2>/dev/null | head -1)"
[ -n "$IMAGEFILES" ] || { echo "错误: 未找到 device/soc/unisoc 下的 ImageFiles 目录（flash.cfg）" >&2; exit 1; }
FLASH_CFG="$IMAGEFILES/flash.cfg"
SOC_XML="$(ls "$IMAGEFILES"/*.xml 2>/dev/null | grep -v secboot | head -1)"
[ -n "$SOC_XML" ] || { echo "错误: ImageFiles 下无 SoC 配置 XML" >&2; exit 1; }

echo "产品: $PRODUCT    镜像: $IMAGES_DIR"
echo "ImageFiles(FDL/映射): $IMAGEFILES    SoC XML: $(basename "$SOC_XML")"
echo ""

# ---------- 刷机工具选择 ----------
# auto: 有官方 PAC 时优先 CmdDloader（走展锐 U2S 串口，经验证可用）；否则用 spd_dump
PAC_LOCAL="$(ls "$IMAGES_DIR"/*.pac 2>/dev/null | head -1)"
if [ "$TOOL_MODE" = "auto" ]; then
    if [ -n "$PAC_LOCAL" ]; then TOOL_MODE="cmdloader"; else TOOL_MODE="spd_dump"; fi
fi
echo "刷机工具路线: $TOOL_MODE"
echo ""

# ==================== CmdDloader 路线（官方 PAC，全自动） ====================
# 依据: 设备进入下载模式后绑定展锐 U2S 串口驱动，spd_dump(libusb) 无法打开；
#       官方 CmdDloader 走 COM 口，且可经 [Options] Reset=1 在刷完后自动复位。
download_mode_present() {
    local n
    n="$(win_ssh "powershell -NoProfile -Command \"(Get-PnpDevice -PresentOnly | Where-Object InstanceId -match 'VID_1782' | Measure-Object).Count\"" 2>/dev/null | tr -d '\r' | tr -dc '0-9')"
    [ "${n:-0}" -gt 0 ]
}

device_online() {
    win_hdc list targets 2>/dev/null | tr -d '\r' | grep -v "Empty" | grep -q .
}

# 设备"可用就绪"（hdc 刚上线时 /system 可能尚未挂载，此时查库会全部"设备缺失"）
device_ready() {
    win_hdc_shell "ls /system/lib64 2>/dev/null | head -1" 2>/dev/null | tr -d '\r' | grep -q '[A-Za-z0-9]'
}

wait_device_ready() {
    local i
    for i in $(seq 1 90); do
        if device_ready; then
            echo "[就绪] 设备文件系统已可用（${i}0s）"
            return 0
        fi
        sleep 10
    done
    echo "[警告] 设备 hdc 在线但 900s 内文件系统仍不可用" >&2
    return 1
}

enter_download_mode() {
    if download_mode_present; then
        echo "[下载模式] 设备已在下载模式（VID_1782 在场）"
        return 0
    fi
    if device_online; then
        echo "[下载模式] 设备在线 → hdc shell reboot autodloader"
        win_hdc_shell "reboot autodloader" > /dev/null 2>&1 || true
    else
        echo "[下载模式] 设备不在线，等待手动进入（按住 VOL+ 上电/接 USB）..." >&2
    fi
    local i
    for i in $(seq 1 60); do
        if download_mode_present; then
            echo "[下载模式] 已进入（${i}s）"
            return 0
        fi
        sleep 1
    done
    echo "[下载模式] 60s 内未检测到 VID_1782 设备" >&2
    return 1
}

flash_via_cmdloader() {
    local exe todir pac_name pac_win wmd5 lmd5
    [ -n "$PAC_LOCAL" ] || { echo "错误: $IMAGES_DIR 下无 .pac，CmdDloader 路线不可用" >&2; return 1; }
    pac_name="$(basename "$PAC_LOCAL")"

    if exe="$(flash_find_tool_win CmdDloader.exe)"; then
        echo "[环境OK] 工具: $exe"
    else
        echo "[缺工具] Windows 侧未找到 CmdDloader.exe（展锐 ResearchDownload 工具包）" >&2
        flash_env_guidance
        return 1
    fi
    if flash_check_driver_win 1782; then
        echo "[环境OK] 驱动: VID_1782(SPRD) 已安装"
    else
        echo "[缺驱动] Windows 侧无 VID_1782(SPRD) 驱动（见 $DOC §2）" >&2
        return 1
    fi
    todir="${exe%\\*}"
    pac_win="$WIN_DIR_BS\\flash\\pac\\$pac_name"

    # PAC 增量同步（md5 一致则跳过）
    win_ssh "if not exist \"$WIN_DIR_BS\\flash\\pac\" mkdir \"$WIN_DIR_BS\\flash\\pac\"" > /dev/null 2>&1
    wmd5="$(win_ssh "certutil -hashfile \"$pac_win\" MD5" 2>/dev/null | tr -d '\r\000' | grep -aE '^[0-9a-f]{32}$' | head -1)"
    lmd5="$(md5sum "$PAC_LOCAL" | cut -d' ' -f1)"
    if [ "$wmd5" = "$lmd5" ] && [ -n "$lmd5" ]; then
        echo "[跳过] PAC md5 一致 ($pac_name)"
    else
        echo "传输 PAC 到 Windows: $pac_name ($(du -h "$PAC_LOCAL" | cut -f1))"
        $SCP_CMD "$PAC_LOCAL" "$WIN_USER@127.0.0.1:$WIN_DIR/flash/pac/$pac_name" || return 1
    fi

    # 官方工具配置: 刷完自动复位 + 输出机读报告（幂等）
    win_ssh "powershell -NoProfile -Command \"\$p='$todir\\ResearchDownload.ini'; if (Test-Path \$p) { \$c=Get-Content \$p; \$c=\$c -replace '^Reset=0','Reset=1'; \$c=\$c -replace '^enable= 0','enable= 1'; Set-Content -Path \$p -Value \$c -Encoding ASCII }\"" > /dev/null 2>&1 || true

    enter_download_mode || return 1

    echo "==== 执行刷机（CmdDloader）===="
    local runlog="$LOG_DIR/flash_cmdloader_$(date +%Y%m%d_%H%M%S).log"
    ( win_ssh "cd /d $todir && CmdDloader.exe -pac $pac_win" > "$runlog" 2>&1 ) &
    local wpid=$!
    local elapsed=0 max=$(( WAIT_SECS > 900 ? WAIT_SECS : 900 ))
    while kill -0 "$wpid" 2>/dev/null; do
        sleep 5; elapsed=$((elapsed + 5))
        if [ "$elapsed" -ge "$max" ]; then
            echo "[超时] ${max}s 未完成，强制终止刷机进程并尝试恢复" >&2
            kill "$wpid" 2>/dev/null || true
            win_ssh "taskkill /F /IM CmdDloader.exe 2>nul & taskkill /F /IM ResearchDownload.exe 2>nul" > /dev/null 2>&1 || true
            return 1
        fi
    done
    wait "$wpid" 2>/dev/null || true
    echo "刷机进程退出（等待 ${elapsed}s），日志: $runlog"

    # 等待设备回到系统（Reset=1 后应自动重启）
    local i
    for i in $(seq 1 90); do
        if device_online; then
            echo "[OK] 设备已重启回系统（${i}s）"
            wait_device_ready || true
            echo "后续: test/check_sync.sh 复验同步状态，然后跑测试"
            return 0
        fi
        sleep 2
    done
    echo "[失败] 刷机结束但设备未回到系统（仍停在下载模式）" >&2
    echo "       日志尾部:" >&2
    tail -5 "$runlog" 2>/dev/null | sed 's/^/         /' >&2
    return 1
}

# ---------- 环境自检 / 首次准备引导 ----------
win_tool_exists() {   # <exe> → 打印 Windows 侧路径；快速检查（约定目录 + PATH）
    local p
    p="$(win_ssh "if exist \"$WIN_DIR_BS\\bin\\$1\" echo $WIN_DIR_BS\\bin\\$1" 2>/dev/null | tr -d '\r' | head -1)"
    [ -n "$p" ] && { echo "$p"; return 0; }
    p="$(win_ssh "where $1 2>nul" 2>/dev/null | tr -d '\r' | head -1)"
    [ -n "$p" ] && { echo "$p"; return 0; }
    return 1
}

flash_env_guidance() {
    local spd_hint
    if spd_hint="$(win_tool_exists spd_dump.exe)"; then
        spd_hint="已就绪: $spd_hint"
    else
        spd_hint="未部署（按方案B 第1-2 步）"
    fi
    cat >&2 <<EOF

──────────────── 首次准备：两条路线（任选其一） ────────────────
以下命令均在 skill 目录执行:  cd $SKILL_DIR

方案A｜已有展锐 ResearchDownload 工具包（推荐）
  1) 在 Windows 上解压（目录含 CmdDloader.exe / ResearchDownload.exe / Driver\\）
  2) 让脚本找到它（二选一）：
     a) 重跑初始化向导（会自动发现并写入配置）:  test/tunnel/init.sh
     b) 手工登记:
        echo 'FLASH_TOOL_DIR="D:/<解压目录>/SPD_Research_Tool_XXX"' >> $CONF_FILE
     或把整个工具目录复制到  $WIN_DIR_BS\\bin\\

方案B｜没有厂商工具包（当前仅部分可用，已实测）
  ⚠ 仓库自带 wdi-simple.exe 无法绑定 WinUSB：libwdi 构建时无 WDK（#undef WDK_DIR），
    只生成 CDC/usbser INF → spd_dump 报 libusb_open_device failed（2026-11-05 实测）。
  临时可行替代：用 Zadig（公开工具 https://zadig.akeo.ie）对
    VID_1782 / PID_4D00 安装 WinUSB 驱动（Options→List All Devices 勾选），然后:
      bash flash/flash.sh wukong100 --tool=spd_dump --spl=ufs --yes
  长期修复：在有 WDK 的 Windows 环境重建 wdi-simple（ensure_bin.sh 需 WDK_DIR），
    或直接使用方案A 的厂商工具包。

当前 spd_dump: $spd_hint
详解: $DOC §0（通用工具链） / §2（wukong100 驱动与下载模式）
───────────────────────────────────────────────────────────
EOF
}

check_env_report() {
    local rc=0 dev p
    echo "==== 刷机环境自检（wukong100）===="
    if check_tunnel > /dev/null 2>&1; then echo "[1/6] 隧道         OK"; else echo "[1/6] 隧道         FAIL（Windows 侧隧道未运行）"; rc=1; fi
    dev="$(win_hdc list targets 2>/dev/null | tr -d '\r' | grep -v "Empty" | grep -v '^$' | head -1)"
    if [ -n "$dev" ]; then
        echo "[2/6] hdc 目标     $dev"
        echo "[3/6] 设备状态     在线（系统运行中）"
    elif download_mode_present; then
        echo "[2/6] hdc 目标     无（设备已在下载模式）"
        echo "[3/6] 设备状态     下载模式（VID_1782）"
    else
        echo "[2/6] hdc 目标     无"; echo "[3/6] 设备状态     未发现（检查 USB/供电）"; rc=1
    fi
    if p="$(flash_find_tool_win CmdDloader.exe 2>/dev/null)"; then
        echo "[4/6] CmdDloader   $p"
    else
        echo "[4/6] CmdDloader   未找到"; rc=1
    fi
    if p="$(win_tool_exists spd_dump.exe)"; then
        echo "      spd_dump     $p"
    else
        echo "      spd_dump     未部署（可选，见方案B）"
    fi
    if flash_check_driver_win 1782; then
        echo "[5/6] SPD 驱动     OK（驱动库含 VID_1782）"
    else
        echo "[5/6] SPD 驱动     未安装（方案A 装 Driver\\，或方案B 用 wdi-simple 绑 WinUSB）"; rc=1
    fi
    if [ -n "$PAC_LOCAL" ]; then
        echo "[6/6] PAC          $(basename "$PAC_LOCAL") ($(du -h "$PAC_LOCAL" | cut -f1))"
    else
        echo "[6/6] PAC          未找到（先编译出 out/$PRODUCT/packages/phone/images/*.pac）"; rc=1
    fi
    echo ""
    if [ "$rc" -ne 0 ]; then
        flash_env_guidance
    else
        echo "环境就绪：可直接运行 flash/flash.sh $PRODUCT --yes"
    fi
    return "$rc"
}

bootstrap_tools() {
    echo "==== 构建/部署仓库自带刷机工具（不依赖厂商工具包）===="
    local miss=() f
    for f in spd_dump.exe libusb-1.0.dll wdi-simple.exe; do
        [ -f "$SKILL_DIR/bin/$f" ] || miss+=("$f")
    done
    if [ ${#miss[@]} -gt 0 ]; then
        echo "本地缺少: ${miss[*]} → 调用 bin/ensure_bin.sh 构建"
        bash "$SKILL_DIR/bin/ensure_bin.sh" || { echo "构建失败（详见 bin/BUILD.md）" >&2; return 1; }
    fi
    echo "部署到 Windows: $WIN_DIR_BS\\bin"
    win_ssh "if not exist \"$WIN_DIR_BS\\bin\" mkdir \"$WIN_DIR_BS\\bin\"" > /dev/null 2>&1
    $SCP_CMD "$SKILL_DIR/bin/spd_dump.exe" "$SKILL_DIR/bin/libusb-1.0.dll" "$SKILL_DIR/bin/wdi-simple.exe" \
        "$WIN_USER@127.0.0.1:$WIN_DIR/bin/" || return 1
    echo "[OK] 已部署: spd_dump.exe / libusb-1.0.dll / wdi-simple.exe"
    echo ""
    echo "⚠ 注意: 仓库自带 wdi-simple 当前无法绑定 WinUSB（libwdi 构建无 WDK，只会生成 usbser INF，"
    echo "         实测 spd_dump 会报 libusb_open_device failed）。若没有厂商包，请改用 Zadig"
    echo "         （https://zadig.akeo.ie）为 VID_1782/PID_4D00 安装 WinUSB。"
    echo ""
    echo "绑定 WinUSB 之后（厂商包或 Zadig 均可）："
    echo "  设备在线时刷机:"
    echo "     bash $SKILL_DIR/flash/flash.sh wukong100 --tool=spd_dump --spl=ufs --yes"
    echo ""
    echo "说明: 绑定 WinUSB 后厂商 CmdDloader 将不再识别该设备；如需回退，"
    echo "      在设备管理器中对该设备\"更新驱动程序\"→自动搜索，即可恢复展锐 U2S 驱动（驱动库已有 oem*.inf）。"
}

if [ "$BOOTSTRAP" -eq 1 ]; then
    bootstrap_tools
    exit $?
fi

if [ "$CHECK_ENV" -eq 1 ]; then
    check_env_report
    exit $?
fi

if [ "$TOOL_MODE" = "cmdloader" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[DRY-RUN] 工具路线: CmdDloader（官方 PAC）"
        echo "  PAC: $(basename "$PAC_LOCAL")（传输到 $WIN_DIR_BS\\flash\\pac\\）"
        echo "  进入下载模式: hdc shell reboot autodloader（设备在线时）"
        echo "  刷完复位: ResearchDownload.ini [Options] Reset=1"
        exit 0
    fi
    flash_via_cmdloader || exit 1
    exit 0
fi

# ---------- Windows 侧环境三查 ----------
# [工具] spd_dump.exe 动态发现（探测链: env.conf 登记→约定目录→PATH→用户目录扫描）
SPD_EXE_WIN=""
flash_env_check() {
    local missing=0
    if SPD_EXE_WIN="$(flash_find_tool_win spd_dump.exe)"; then
        echo "[环境OK] 工具: $SPD_EXE_WIN"
    else
        echo "[缺工具] Windows 侧未找到 spd_dump.exe（已探测: env.conf 登记位置 → \$WIN_DIR\\bin → PATH → 用户目录扫描）" >&2
        missing=1
    fi
    if flash_check_driver_win 1782; then
        echo "[环境OK] 驱动: VID_1782(SPRD) 已安装"
    else
        echo "[缺驱动] Windows 侧无 VID_1782(SPRD) 驱动" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        echo "" >&2
        echo "环境准备步骤详见 $DOC（§0 通用 + §2 wukong100）:" >&2
        echo "  1. 服务器执行: bash $SKILL_DIR/bin/ensure_bin.sh --only=spd-dump     （构建 spd_dump.exe）" >&2
        echo "  2. 部署: scp -P $TUNNEL_PORT $SKILL_DIR/bin/spd_dump.exe $SKILL_DIR/bin/libusb-1.0.dll <win>:\$WIN_DIR\\bin\\  （或按 §0 登记位置）" >&2
        echo "  3. 驱动: 按 §2 安装 SPD USB 驱动（或 wdi-simple 绑定 WinUSB）" >&2
        echo "  4. 重新执行本命令" >&2
        return 1
    fi
    return 0
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "==== [DRY-RUN 模式] 环境检查仅报告，不阻断 ===="
    flash_env_check || true
    echo ""
else
    flash_env_check || exit 1
    echo ""
fi

# ---------- 从 XML 提取 FDL 地址与 角色→分区 权威映射 ----------
parse_xml_map() {
python3 - "$SOC_XML" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
for f in tree.iter('File'):
    fid, typ = f.findtext('ID'), f.findtext('Type')
    block = f.find('Block')
    bid = block.get('id') if block is not None else ''
    base = block.findtext('Base') if block is not None else ''
    if fid in ('FDL', 'FDL2'):   # FDL=FDL 类型, FDL2=NAND_FDL 类型, 按 ID 匹配
        print(f"FDLBASE\t{fid}\t{base}")
    else:
        print(f"MAP\t{fid}\t{bid}")
PYEOF
}

declare -A ROLE_PART FDL_BASE
while IFS=$'\t' read -r kind key val; do
  [ -z "${kind:-}" ] && continue
  if [ "$kind" = "FDLBASE" ]; then FDL_BASE["$key"]="$val"; else ROLE_PART["$key"]="$val"; fi
done < <(parse_xml_map)

FDL1_ADDR="${FDL_BASE[FDL]:-}"
FDL2_ADDR="${FDL_BASE[FDL2]:-}"
[ -n "$FDL1_ADDR" ] && [ -n "$FDL2_ADDR" ] || { echo "错误: XML 中未解析到 FDL/FDL2 装载地址" >&2; exit 1; }
echo "FDL1 装载地址: $FDL1_ADDR    FDL2 装载地址: $FDL2_ADDR"

# 特殊角色 → 实际分区（XML 之外的工具语义，官方 pac 刷机行为）
ROLE_PART[EraseUBOOT]="uboot_a uboot_b"   # 擦两个槽位（随后 UBOOTLoader 写 _a）
ROLE_PART[FLASH_NR]="${ROLE_PART[FLASH_NR]:-nr_runtimenv1}"

# ---------- SPL 变体选择（互斥！两个变体同写 splloader 分区会互相覆盖） ----------
detect_storage_on_device() {
    local blocks
    blocks="$(dt_device_shell "ls /sys/block/" 2>/dev/null | tr -d '\r')" || return 1
    if grep -q "^mmcblk" <<< "$blocks"; then echo "emmc"; return 0; fi
    if grep -qE "^sd[a-z]" <<< "$blocks"; then echo "ufs"; return 0; fi
    return 1
}

SPL_PROBE_NOTE=""
if [ -z "$SPL_VARIANT" ]; then
  SPL_VARIANT="$(detect_storage_on_device)" && SPL_PROBE_NOTE="设备自动探测(/sys/block)" || SPL_VARIANT=""
fi
if [ -z "$SPL_VARIANT" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[警告] SPL 变体未确定: 设备不可达（可能已关机）且未指定 --spl=emmc|ufs。" >&2
    echo "        以下计划按 UFS 假设展示——真实刷机前必须确认!" >&2
    SPL_VARIANT="ufs"; SPL_PROBE_NOTE="假设(未验证!)"
  else
    if [ "$ASSUME_YES" -eq 1 ]; then
      echo "错误: 设备离线且未指定存储类型（自动化模式必须显式加 --spl=emmc|ufs）" >&2
      exit 1
    fi
    echo "设备存储类型未知（设备可能已关机进入下载模式）。"
    read -rp "SPL 变体选择 emmc 还是 ufs? [emmc/ufs]: " SPL_VARIANT
    case "$SPL_VARIANT" in
      emmc|ufs) ;;
      *) echo "错误: 无效选择 '$SPL_VARIANT'" >&2; exit 1 ;;
    esac
    SPL_PROBE_NOTE="人工指定"
  fi
else
  case "$SPL_VARIANT" in
    emmc|ufs) ;;
    *) echo "错误: --spl 只接受 emmc 或 ufs" >&2; exit 1 ;;
  esac
fi
echo "SPL 变体: $SPL_VARIANT ($SPL_PROBE_NOTE)"
echo ""

# ---------- 解析 flash.cfg 生成操作计划 ----------
find_image() {   # 角色文件查找: images/ 优先, ImageFiles 兜底；输出本地路径与文件名
  local f="$1"
  [ -f "$IMAGES_DIR/$f" ] && { echo "$IMAGES_DIR/$f"; return 0; }
  [ -f "$IMAGEFILES/$f" ] && { echo "$IMAGEFILES/$f"; return 0; }
  return 1
}

is_skipped() { [ -n "$SKIP_ROLES" ] && grep -qw "$1" <<< "$SKIP_ROLES"; }

OPS=()          # spd_dump 命令段（write_part/erase_part，文件用文件名——Windows 侧staging目录内相对路径）
STAGE_FILES=()  # 需传输到 Windows staging 的文件
PLAN=()
UNKNOWN=()

while IFS= read -r line; do
  line="${line%%#*}"
  [[ "$line" =~ ^\[(.*)\]$ ]] && continue
  [[ "$line" =~ ^[[:space:]]*$ ]] && continue
  [[ "$line" =~ ^([A-Za-z_0-9]+)=([01])@(.*)$ ]] || continue
  role="${BASH_REMATCH[1]}"; flag="${BASH_REMATCH[2]}"; file="${BASH_REMATCH[3]}"
  [ "$flag" = "0" ] && continue
  case "$role" in
    FDL|FDL2) continue ;;                          # 由专门的 fdl 命令处理
    FLASH_LTE) continue ;;                         # 空文件标记, 工具内部行为
  esac
  is_skipped "$role" && { PLAN+=("[跳过] $role (用户指定 --skip)"); continue; }
  if [ "$role" = "ProdNV" ] && [ "$INCLUDE_NV" -eq 0 ]; then
    PLAN+=("[跳过] ProdNV → prodnv（默认保留板上 NV；重置 NV 用 --include-nv）")
    continue
  fi
  # SPL 变体互斥: 只写入选中变体, 另一个跳过（两者同写 splloader 会互相覆盖!）
  case "$role" in
    SPLLoaderEMMC) if [ "$SPL_VARIANT" != "emmc" ]; then
        PLAN+=("[跳过] SPLLoaderEMMC（SPL 变体已选 $SPL_VARIANT）"); continue
      fi ;;
    SPLLoaderUFS)  if [ "$SPL_VARIANT" != "ufs" ]; then
        PLAN+=("[跳过] SPLLoaderUFS（SPL 变体已选 $SPL_VARIANT）"); continue
      fi ;;
  esac
  part="${ROLE_PART[$role]:-}"
  if [ -z "$part" ]; then
    UNKNOWN+=("$role")
    PLAN+=("[未知] $role=1@$file（XML 无映射, 已跳过——请人工确认）")
    continue
  fi
  if [ -z "$file" ]; then
    for p in $part; do OPS+=("erase_part" "$p"); PLAN+=("擦除   $p   ($role)"); done
    continue
  fi
  img="$(find_image "$file")" || { PLAN+=("[缺文件] $role=1@$file"); UNKNOWN+=("$role(file)"); continue; }
  first_part="$(awk '{print $1}' <<< "$part")"   # A/B 槽位: 官方 pac 条目映射到 _a 槽
  OPS+=("write_part" "$first_part" "$(basename "$img")")
  STAGE_FILES+=("$img")
  PLAN+=("写入   $first_part   <= $(basename "$img")   ($role)")
done < "$FLASH_CFG"

# FDL 文件也需传输
STAGE_FILES+=("$IMAGEFILES/fdl1-sign.bin" "$IMAGEFILES/lk-fdl2-sign.bin")

echo "================= 刷机操作计划 (flash.cfg + $(basename "$SOC_XML")) ================="
printf '  %s\n' "${PLAN[@]}"
echo "====================================================================="
if [ ${#UNKNOWN[@]} -gt 0 ]; then
  echo "警告: ${#UNKNOWN[@]} 个条目无映射或缺文件: ${UNKNOWN[*]}" >&2
fi
echo ""

# ---------- Windows 侧 staging 路径（镜像传输目的地与执行 cwd） ----------
STAGE_WIN="$WIN_DIR/flash/wukong100"
STAGE_WIN_BS="$WIN_DIR_BS\\flash\\wukong100"
SPD_PREVIEW="${SPD_EXE_WIN:-<spd_dump.exe 路径——未部署, 见上方环境提示>}"

echo "将执行(Windows 侧): cd /d $STAGE_WIN_BS && $SPD_PREVIEW --wait $WAIT_SECS keep_charge 1 \\"
echo "  fdl fdl1-sign.bin $FDL1_ADDR  fdl lk-fdl2-sign.bin $FDL2_ADDR  exec  <操作序列(${#OPS[@]} 段)>  reset"
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[DRY-RUN] 未传输任何文件、未执行任何写操作。"
  exit 0
fi

# ---------- 交互确认 ----------
if [ "$ASSUME_YES" -ne 1 ]; then
  echo "!!! 刷机是毁灭性操作, 将覆写上述分区 !!!"
  read -rp "确认继续请输入 yes: " ACK
  [ "$ACK" = "yes" ] || { echo "已取消。"; exit 1; }
fi

# ---------- 镜像传输（md5 增量: 已一致则跳过） ----------
win_md5() {   # Windows 侧文件 md5（certutil）
  win_ssh "certutil -hashfile \"$1\" MD5" 2>/dev/null | tr -d '\r\000' | grep -aE '^[0-9a-f]{32}$' | head -1
}
stage_file() {   # stage_file <本地路径> <staging 文件名>
  local local_f="$1" name="$2" wmd5 lmd5
  wmd5="$(win_md5 "$STAGE_WIN_BS\\$name" || true)"
  lmd5="$(md5sum "$local_f" | cut -d' ' -f1)"
  if [ "$wmd5" = "$lmd5" ] && [ -n "$lmd5" ]; then
    echo "  [跳过] $name (md5 一致)"
    return 0
  fi
  $SCP_CMD "$local_f" "$WIN_USER@127.0.0.1:$STAGE_WIN/$name"
  echo "  [传输] $name"
}

echo "==== 传输镜像与 FDL 到 Windows staging: $STAGE_WIN ===="
win_ssh "(if not exist $STAGE_WIN_BS mkdir $STAGE_WIN_BS)" || exit 1
declare -A STAGED_SEEN
for f in "${STAGE_FILES[@]}"; do
  n="$(basename "$f")"
  [ -n "${STAGED_SEEN[$n]:-}" ] && continue    # 同名文件只传一次
  STAGED_SEEN["$n"]=1
  stage_file "$f" "$n"
done
echo ""

# ---------- 执行刷机（Windows 侧 spd_dump.exe） ----------
echo "==== 执行刷机 ===="
echo "把板子置于下载模式: 在线时执行  hdc shell reboot autodloader  ；或按住 音量+(VOL+) 接 USB"
echo "（spd_dump --wait $WAIT_SECS 等待设备出现...）"
win_ssh "cd /d $STAGE_WIN_BS && \"$SPD_EXE_WIN\" --wait $WAIT_SECS keep_charge 1 fdl fdl1-sign.bin $FDL1_ADDR fdl lk-fdl2-sign.bin $FDL2_ADDR exec ${OPS[*]} reset"
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
echo "[WARN] 120 秒内未见设备回来——请检查板子（刷机失败时设备可能停留在下载模式，重新执行本脚本）" >&2
exit 1
