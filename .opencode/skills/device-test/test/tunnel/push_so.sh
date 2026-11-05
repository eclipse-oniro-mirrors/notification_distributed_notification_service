#!/bin/bash
# ============================================================================
# push_so.sh - 部件 so 增量推送到板子（板上路径探测 + remount + 备份 + md5 校验）
# 用法: push_so.sh <part>
# 示例: push_so.sh hitrace
# 逻辑:
#   1. 定位部件产物目录 out/**/<part>/*.so
#   2. 对每个 so: 在板上 find /system /vendor /sys_prod /chip_prod 探测实际路径
#      - 找到(可多处) -> 逐处备份后覆盖
#      - 未找到       -> 视为新库，推到 /system/lib 并提示
#   3. 每处推送后双端 md5 校验
# 注意: 产物版本必须与板子系统匹配（跨版本请先刷镜像）；
#       已加载旧 so 的服务需重启（或重启板子）才生效
# ============================================================================
source "$(dirname "$0")/common.sh"
[ $# -lt 1 ] && { echo "用法: $0 <part>  例: $0 hitrace"; exit 1; }
require_config || exit 1
cd "$CODE_DIR" || exit 1
PART="$1"

check_tunnel || exit 1
check_board || exit 1

OUTDIR=$(find out/$PRODUCT_NAME -maxdepth 2 -type d -name "$PART" ! -path "*/tests/*" ! -path "*/obj/*" 2>/dev/null | head -1)
[ -z "$OUTDIR" ] && { echo "[ERROR] 未找到部件产物目录 out/**/$PART"; exit 1; }
mapfile -t SOS < <(ls "$OUTDIR"/*.so 2>/dev/null)
[ ${#SOS[@]} -eq 0 ] && { echo "[ERROR] $OUTDIR 下无 .so"; exit 1; }
echo "[SO] ${#SOS[@]} 个 so: $(basename -a "${SOS[@]}" | tr '\n' ' ')"

hdc_shell() {  # 在板上执行命令(经隧道)
    win_ssh "set PATH=$TOOLCHAINS_DIR;%PATH% && $HDC_EXE shell \"$*\""
}

for so in "${SOS[@]}"; do
    name=$(basename "$so")
    echo "  push $name"

    # ---- 板上实际路径探测 ----
    mapfile -t DSTS < <(hdc_shell "find /system /vendor /sys_prod /chip_prod -name $name 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -v "^$" | grep -v "find:" | sort -u)
    if [ ${#DSTS[@]} -eq 0 ]; then
        DEFLIB=$(hdc_shell "ls -d /system/lib64 2>/dev/null" 2>/dev/null | tr -d '\r')
        [ -z "$DEFLIB" ] && DEFLIB="/system/lib"
        DSTS=("$DEFLIB/$name")
        echo "      [WARN] 板上未找到 $name，按新库推到默认 $DEFLIB"
    else
        echo "      板上实际路径(${#DSTS[@]}处): ${DSTS[*]}"
    fi

    win_ssh "(if not exist $WIN_DIR_BS\\tmp mkdir $WIN_DIR_BS\\tmp)" || exit 1
    $SCP_CMD "$so" "$WIN_USER@127.0.0.1:$WIN_TMP/" || exit 1

    for dst in "${DSTS[@]}"; do
        # 按目标所在分区 remount
        part="/"
        case "$dst" in
            /vendor/*)   part="/vendor" ;;
            /sys_prod/*) part="/sys_prod" ;;
            /chip_prod/*) part="/chip_prod" ;;
        esac
        bak="/data/backup_$(echo "$dst" | tr '/' '_')"
        win_ssh "set PATH=$TOOLCHAINS_DIR;%PATH% && $HDC_EXE shell \"remount 2>/dev/null ; mount -o remount,rw $part 2>/dev/null ; cp $dst $bak 2>/dev/null ; echo backup_done\" && $HDC_EXE file send $WIN_DIR_BS\\tmp\\$name $dst && $HDC_EXE shell chmod 644 $dst" \
            || { echo "[ERROR] $name -> $dst 推送失败"; exit 1; }
        m1=$(md5sum "$so" | cut -d' ' -f1)
        m2=$(win_ssh "set PATH=$TOOLCHAINS_DIR;%PATH% && $HDC_EXE shell md5sum $dst" 2>/dev/null | cut -d' ' -f1)
        [ "$m1" = "$m2" ] && echo "      $dst md5 OK ($m1)" || { echo "      [WARN] $dst md5 不一致! $m1 vs $m2"; exit 1; }
    done
    win_ssh "del $WIN_DIR_BS\\tmp\\$name" 2>/dev/null   # 清理中转文件
done
echo "[SO] 完成。如服务进程已加载旧 so，需重启对应服务或重启板子生效"
