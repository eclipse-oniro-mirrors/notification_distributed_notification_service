#!/bin/bash
# ============================================================================
# ensure_bin.sh - 刷机工具链自举（bin/ 不携带二进制产物，首次使用从上游源码构建）
#
# 构建产物（刷机工具链，全部为 Windows 侧工具，经隧道在 Windows 执行）:
#   rkdeveloptool.exe + libusb-1.0.dll   RK/Rockchip 分区烧写工具及其 USB 后端
#   wdi-simple.exe                       WinUSB 驱动全自动安装（libwdi 引擎，同 Zadig：
#                                        生成 INF + 运行时自签证书 + 导入信任链 + 安装）
#   spd_dump.exe                         Unisoc/SPRD 板刷机工具（FDL 协议 + 分区读写）
#
# 用法: ensure_bin.sh [--force] [--only=rkdeveloptool|libusb|wdi-simple|spd-dump] [--help]
#   --force          已存在的产物也强制重建
#   --only=<组件>    只构建指定组件
#
# 幂等: 产物存在且格式正确则跳过；WORK 环境变量可指定构建目录（默认 bin/build/）
# 上游固定版本与手动重建细节见同目录 BUILD.md。
# 依赖: mingw-w64(x86_64+i686) autoconf automake libtool(pkg-config) make patch curl git
set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$BIN_DIR/build}"
FORCE=0
ONLY=""

# 上游固定版本（可用环境变量覆盖）
LIBUSB_TARBALL_URL="${LIBUSB_URL:-https://github.com/libusb/libusb/releases/download/v1.0.26/libusb-1.0.26.tar.bz2}"
LIBUSB_MD5="${LIBUSB_MD5:-9c75660dfe1d659387c37b28c91e3160}"
RKT_REPO="${RKT_REPO:-https://github.com/zxySeaStar/rkdeveloptool-win32.git}"
RKT_COMMIT="${RKT_COMMIT:-71d3cbe}"
LIBWDI_REPO="${LIBWDI_REPO:-https://github.com/pbatard/libwdi.git}"
LIBWDI_COMMIT="${LIBWDI_COMMIT:-30df0c0}"
SPD_REPO="${SPD_REPO:-https://github.com/ilyakurdyukov/spreadtrum_flash.git}"
SPD_COMMIT="${SPD_COMMIT:-3d05825}"

for arg in "$@"; do
  case "$arg" in
    --force)    FORCE=1 ;;
    --only=*)   ONLY="${arg#--only=}" ;;
    --help|-h)  sed -n '2,19p' "$0"; exit 0 ;;
    --*)        echo "错误: 未知选项 '$arg' (运行 --help 查看可用选项)" >&2; exit 2 ;;
    *)          echo "错误: 不接受位置参数 '$arg'" >&2; exit 2 ;;
  esac
done

VALID_ONLY="rkdeveloptool libusb wdi-simple spd-dump"
if [ -n "$ONLY" ] && ! grep -qw "$ONLY" <<< "$VALID_ONLY"; then
  echo "错误: 无效组件 '$ONLY'。可选: $VALID_ONLY" >&2
  exit 2
fi

# ---------- 环境自检 ----------
check_dep() {
  command -v "$1" > /dev/null 2>&1 || { echo "错误: 缺少依赖 '$1'。请先安装（如: sudo apt-get install $2）" >&2; exit 1; }
}
need_mingw() { check_dep x86_64-w64-mingw32-gcc mingw-w64; }
need_mingw32() { check_dep i686-w64-mingw32-gcc gcc-mingw-w64-i686; }
check_dep make make
check_dep patch patch
check_dep curl curl
check_dep git git

want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }   # 未指定 --only 或指定当前组件

is_pe() { [ -f "$1" ] && file "$1" | grep -q "PE.*executable"; }

ensure_dir() { mkdir -p "$1"; }

# ---------- 组件1: libusb-1.0.dll（rkdeveloptool 的 USB 后端） ----------
build_libusb() {
  ensure_dir "$WORK"
  local tarball="$WORK/$(basename "$LIBUSB_TARBALL_URL")"
  local srcdir="$WORK/libusb-1.0.26"
  if [ -f "$tarball" ]; then
    echo "[libusb] 复用已下载源码包 $tarball"
  else
    echo "[libusb] 下载 $LIBUSB_TARBALL_URL ..."
    curl -sL -o "$tarball" "$LIBUSB_TARBALL_URL"
  fi
  local md5
  md5="$(md5sum "$tarball" | cut -d' ' -f1)"
  [ "$md5" = "$LIBUSB_MD5" ] || { echo "错误: libusb 源码包 md5 校验失败 ($md5 != $LIBUSB_MD5)" >&2; exit 1; }
  [ -d "$srcdir" ] || tar xf "$tarball" -C "$WORK"
  if [ ! -f "$WORK/prefix/bin/libusb-1.0.dll" ] || [ "$FORCE" -eq 1 ]; then
    ( cd "$srcdir" && \
      ./configure --host=x86_64-w64-mingw32 --prefix="$WORK/prefix" --disable-udev > "$WORK/libusb_conf.log" 2>&1 && \
      make -j"$(nproc)" > "$WORK/libusb_make.log" 2>&1 && \
      make install > /dev/null 2>&1 )
  fi
  cp "$WORK/prefix/bin/libusb-1.0.dll" "$BIN_DIR/libusb-1.0.dll"
  is_pe "$BIN_DIR/libusb-1.0.dll" || { echo "错误: libusb-1.0.dll 构建产物异常" >&2; exit 1; }
  echo "[libusb] OK -> $BIN_DIR/libusb-1.0.dll"
}

# ---------- 组件2: rkdeveloptool.exe（RK 分区烧写，win32 移植 fork + MinGW 兼容补丁） ----------
git_clone_retry() {  # git_clone_retry <repo> <destdir>（网络抖动自动重试 3 次）
  local repo="$1" dest="$2" i
  for i in 1 2 3; do
    git clone --quiet "$repo" "$dest" && return 0
    echo "[git] 克隆失败(第 $i 次): $repo，重试..."
    rm -rf "$dest"; sleep 3
  done
  echo "错误: 克隆 $repo 失败，请检查网络后重试" >&2
  return 1
}

build_rkdeveloptool() {
  local srcdir="$WORK/rkdeveloptool-win32"
  if [ ! -d "$srcdir/.git" ]; then
    echo "[rkt] 克隆 $RKT_REPO ..."
    git_clone_retry "$RKT_REPO" "$srcdir" || exit 1
  fi
  ( cd "$srcdir" && git fetch --quiet --all > /dev/null 2>&1 || true; \
    git checkout --quiet "$RKT_COMMIT" 2>/dev/null || \
      { echo "错误: 上游不存在固定提交 $RKT_COMMIT（可用环境变量 RKT_REPO/RKT_COMMIT 覆盖，并在 BUILD.md 记录新版本）" >&2; exit 1; } )
  local head
  head="$(git -C "$srcdir" rev-parse --short HEAD)"
  if [ "$head" != "$RKT_COMMIT" ]; then
    echo "错误: 克隆结果 $head != 固定版本 $RKT_COMMIT" >&2; exit 1
  fi
  echo "[rkt] 上游版本 $head + MinGW 兼容补丁"
  ( cd "$srcdir" && git checkout --quiet -- . 2>/dev/null || true; \
    patch -p1 --force --forward --silent < "$BIN_DIR/rkdeveloptool-mingw.patch" )
  ( cd "$srcdir" && autoreconf -i > "$WORK/rkt_autoreconf.log" 2>&1 && \
    PKG_CONFIG_PATH="$WORK/prefix/lib/pkgconfig" ./configure --host=x86_64-w64-mingw32 > "$WORK/rkt_configure.log" 2>&1 && \
    make -j"$(nproc)" > "$WORK/rkt_make.log" 2>&1 )
  cp "$srcdir/rkdeveloptool.exe" "$BIN_DIR/rkdeveloptool.exe"
  is_pe "$BIN_DIR/rkdeveloptool.exe" || { echo "错误: rkdeveloptool.exe 构建产物异常" >&2; exit 1; }
  echo "[rkt] OK -> $BIN_DIR/rkdeveloptool.exe（依赖同目录 libusb-1.0.dll）"
}

# ---------- 组件3: wdi-simple.exe（WinUSB 驱动全自动安装，libwdi 引擎） ----------
# Debian 系 mingw-w64 为单目标编译器（x86_64 不支持 -m32），而 libwdi 全库按 32 位设计，
# 通过 ccwrap shim 将 -m32 调用转发到 i686 编译器解决（见 BUILD.md"构建适配"）。
make_ccwrap() {
  ensure_dir "$WORK/ccwrap"
  cat > "$WORK/ccwrap/x86_64-w64-mingw32-gcc" <<'EOF'
#!/bin/bash
# -m32 时转发到 i686 编译器（Debian mingw 非多库工具链的兼容层）
for a in "$@"; do [ "$a" = "-m32" ] && exec /usr/bin/i686-w64-mingw32-gcc "$@"; done
exec /usr/bin/x86_64-w64-mingw32-gcc "$@"
EOF
  chmod +x "$WORK/ccwrap/x86_64-w64-mingw32-gcc"
}

# x86_64 mingw ld 链接 32 位目标需要 i386pe.x 脚本（Debian 拆在 i686 包前缀下），缺失则尝试补齐
fix_ldscripts() {
  local x64dir=/usr/x86_64-w64-mingw32/lib/ldscripts
  local i686dir=/usr/i686-w64-mingw32/lib/ldscripts
  [ -f "$x64dir/i386pe.x" ] && return 0
  [ -f "$i686dir/i386pe.x" ] || { echo "错误: $i686dir/i386pe.x 不存在，请安装 gcc-mingw-w64-i686" >&2; exit 1; }
  if sudo -n cp "$i686dir"/i386pe.* "$x64dir/" 2>/dev/null; then
    echo "[wdi] 已补齐 $x64dir/i386pe.*（i386pe 链接脚本缺失会卡 32 位嵌入安装器构建）"
  else
    echo "错误: 缺少 $x64dir/i386pe.x。请手动执行后重试:" >&2
    echo "  sudo cp $i686dir/i386pe.* $x64dir/" >&2
    exit 1
  fi
}

build_wdi_simple() {
  need_mingw32
  fix_ldscripts
  make_ccwrap
  ensure_dir "$WORK/wdi_user"   # userdir 只需存在
  # 注意: libwdi 的 WinUSB 类型依赖构建期 WDK_DIR（嵌入 winusb 驱动文件），
  #       未定义时 wdi_is_driver_supported(WDI_WINUSB) 返回 FALSE，wdi-simple 会退化成
  #       CDC/usbser（对 spd_dump/rkdeveloptool 无效）。详见 BUILD.md 构建适配第 6 条。
  local srcdir="$WORK/libwdi"
  if [ ! -d "$srcdir/.git" ]; then
    echo "[wdi] 克隆 $LIBWDI_REPO ..."
    git_clone_retry "$LIBWDI_REPO" "$srcdir" || exit 1
  fi
  ( cd "$srcdir" && git checkout --quiet "$LIBWDI_COMMIT" 2>/dev/null || \
      { echo "错误: 上游不存在固定提交 $LIBWDI_COMMIT" >&2; exit 1; } )
  echo "[wdi] 上游版本 $(git -C "$srcdir" rev-parse --short HEAD)"
  ( cd "$srcdir" && ./autogen.sh > "$WORK/wdi_autogen.log" 2>&1 )
  # 注意: make 整体会在 zadig(GUI，不需要)处失败；wdi-simple.exe 先于该失败产出。
  #       上游 examples 的 %_rc.o 规则漏用 $(ARCH_RCFLAGS)，须命令行传 AM_RCFLAGS 对齐 32 位。
  ( cd "$srcdir" && \
    PATH="$WORK/ccwrap:$PATH" CC=x86_64-w64-mingw32-gcc \
    ./configure --host=x86_64-w64-mingw32 --with-userdir="$WORK/wdi_user" \
      --disable-debug --enable-examples-build > "$WORK/wdi_conf.log" 2>&1 )
  ( cd "$srcdir" && PATH="$WORK/ccwrap:$PATH" CC=x86_64-w64-mingw32-gcc \
    make -j"$(nproc)" AM_RCFLAGS="--target=pe-i386" > "$WORK/wdi_make.log" 2>&1 ) || true
  cp "$srcdir/examples/wdi-simple.exe" "$BIN_DIR/wdi-simple.exe" 2>/dev/null || {
    echo "错误: 未产出 wdi-simple.exe，查看 $WORK/wdi_make.log" >&2; exit 1; }
  is_pe "$BIN_DIR/wdi-simple.exe" || { echo "错误: wdi-simple.exe 构建产物异常" >&2; exit 1; }
  echo "[wdi] OK -> $BIN_DIR/wdi-simple.exe"
}

# ---------- 组件4: spd_dump.exe（Windows 侧，Unisoc/SPRD 板刷机工具，经隧道在 Windows 执行） ----------
# 与前三个组件同链: MinGW 交叉编译，链接本脚本构建的 libusb（prefix/）
build_spd_dump() {
    need_mingw
    local srcdir="$WORK/spreadtrum_flash"
    if [ ! -d "$srcdir/.git" ]; then
        echo "[spd] 克隆 $SPD_REPO ..."
        git_clone_retry "$SPD_REPO" "$srcdir" || exit 1
    fi
    ( cd "$srcdir" && git checkout --quiet "$SPD_COMMIT" 2>/dev/null || \
        { echo "错误: 上游不存在固定提交 $SPD_COMMIT" >&2; exit 1; } )
    echo "[spd] 上游版本 $(git -C "$srcdir" rev-parse --short HEAD)"
    # 注意: 命令行覆盖 CFLAGS 时 Makefile 内的 += 失效, 须自带 -DUSE_LIBUSB=1
    ( cd "$srcdir" && make clean > /dev/null 2>&1; \
      make CC=x86_64-w64-mingw32-gcc \
           CFLAGS="-O2 -Wall -std=c99 -DUSE_LIBUSB=1 -I$WORK/prefix/include" \
           LIBS="-L$WORK/prefix/lib -lusb-1.0" > "$WORK/spd_make.log" 2>&1 )
    cp "$srcdir/spd_dump.exe" "$BIN_DIR/spd_dump.exe"
    is_pe "$BIN_DIR/spd_dump.exe" || { echo "错误: spd_dump.exe 构建产物异常" >&2; exit 1; }
    echo "[spd] OK -> $BIN_DIR/spd_dump.exe（依赖同目录 libusb-1.0.dll；Unlicense）"
}

# ---------- 主流程 ----------
need_mingw
ensure_dir "$WORK"

FAILED=0
if want libusb; then
  if is_pe "$BIN_DIR/libusb-1.0.dll" && [ "$FORCE" -eq 0 ]; then
    echo "[libusb] 已存在，跳过（--force 重建）"
  else
    build_libusb || FAILED=1
  fi
fi
if want rkdeveloptool; then
  if is_pe "$BIN_DIR/rkdeveloptool.exe" && [ "$FORCE" -eq 0 ]; then
    echo "[rkt] 已存在，跳过（--force 重建）"
  else
    build_rkdeveloptool || FAILED=1
  fi
fi
if want wdi-simple; then
  if is_pe "$BIN_DIR/wdi-simple.exe" && [ "$FORCE" -eq 0 ]; then
    echo "[wdi] 已存在，跳过（--force 重建）"
  else
    build_wdi_simple || FAILED=1
  fi
fi
if want spd-dump; then
  if is_pe "$BIN_DIR/spd_dump.exe" && [ "$FORCE" -eq 0 ]; then
    echo "[spd] 已存在，跳过（--force 重建）"
  else
    build_spd_dump || FAILED=1
  fi
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
  echo "=== 自举失败: 构建日志在 $WORK/*.log ===" >&2
  exit 1
fi
echo "=== 自举完成 ==="
ls -la "$BIN_DIR"/*.exe "$BIN_DIR"/*.dll 2>/dev/null || true
echo ""
echo "部署说明（刷机工具全部在 Windows 侧执行）:"
echo "  将本 bin/ 目录内容随 skill 部署到 Windows（约定位置 \$WIN_DIR\\bin\\，见 references/flash-env.md §0）"
echo "  RK3568: 首次装驱动 install_winusb.bat，刷机 flash_rk3568.bat（Loader 模式）"
echo "  wukong100: 刷机由 flash/wukong100/flash.sh 经隧道编排 spd_dump.exe"
