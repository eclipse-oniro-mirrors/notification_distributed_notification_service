# 刷机工具链构建说明（bin/ 自举）

`bin/` 不携带任何二进制产物（合规要求），首次使用由 `ensure_bin.sh` 从上游源码构建。

```bash
bash bin/ensure_bin.sh            # 构建全部（幂等，已有产物跳过）
bash bin/ensure_bin.sh --force    # 强制重建
bash bin/ensure_bin.sh --only=wdi-simple
```

## 成品清单

| 文件 | 用途 | 来源 |
|---|---|---|
| `rkdeveloptool.exe` | Rockchip 命令行烧写（Windows 侧） | `zxySeaStar/rkdeveloptool-win32` @ `71d3cbe` + 本目录 `rkdeveloptool-mingw.patch`（MinGW 兼容 3 处） |
| `libusb-1.0.dll` | rkdeveloptool 的 USB 后端，须与 exe 同目录 | libusb 官方 v1.0.26 release tarball（md5 `9c75660dfe1d659387c37b28c91e3160`） |
| `wdi-simple.exe` | WinUSB 驱动全自动安装（libwdi 引擎，同 Zadig：生成 INF + 运行时自签证书 + 导入信任链 + 安装，**无需 Windows SDK**） | `pbatard/libwdi` @ `30df0c0` |
| `spd_dump.exe` | Unisoc/SPRD 板刷机（FDL 协议 + 分区读写，Windows 侧经隧道执行） | `ilyakurdyukov/spreadtrum_flash` @ `3d05825`（**Unlicense** 公有领域） |

产物目录即本 `bin/`（`build/` 为构建工作目录，已 gitignore）。**全部为 Windows 侧工具**：将 `bin/` 内容部署到 Windows 约定位置（`$WIN_DIR\bin\`，详见 skill 的 `references/flash-env.md §0`）；spd_dump.exe 与 rkdeveloptool.exe 运行时需同目录 `libusb-1.0.dll`。

## 许可证注意

libusb 为 LGPL-2.1，rkdeveloptool（fork 基于 Rockchip 上游）为 GPL-2.0，libwdi 为 LGPL-3.0+，spd_dump 为 **Unlicense（公有领域）**。**本仓库只携带源码级 patch 与构建脚本，二进制产物由使用者首次使用时自行构建自用，不入库、不构成再分发**；升级上游版本时更新本文档固定版本记录。

## 构建适配（踩坑记录，ensure_bin.sh 已自动处理）

1. **Debian 系 mingw-w64 是单目标编译器**（`x86_64-w64-mingw32-gcc` 不支持 `-m32`），而 libwdi 全库按 32 位设计（32 位 exe 可在 x64 Windows 运行）→ `ensure_bin.sh` 生成 ccwrap shim，把带 `-m32` 的调用转发给 `i686-w64-mingw32-gcc`。
2. **`i386pe.x` 链接脚本缺失**：x86_64 mingw ld 支持 i386pe 仿真，但 Debian 把脚本放在 i686 包前缀（`/usr/i686-w64-mingw32/lib/ldscripts/`）→ 需复制到 `/usr/x86_64-w64-mingw32/lib/ldscripts/`（脚本会用 `sudo -n` 尝试，失败时给出手动命令）。
3. **libwdi examples 的 `%_rc.o` 规则漏用 `$(ARCH_RCFLAGS)`**（上游疏漏）：资源文件默认按 64 位 windres 产出，与 32 位库混链报 `file format not recognized` → make 时命令行传 `AM_RCFLAGS="--target=pe-i386"` 对齐。
4. **libwdi 整体 make 会在 zadig（GUI，不需要）编译失败**（wininet 头文件版本问题），`wdi-simple.exe` 先于该失败产出 → 脚本容忍 make 失败、校验产物存在即可。
5. **rkdeveloptool 的 3 处 MinGW 兼容补丁**（`rkdeveloptool-mingw.patch`）：`<Windows.h>`→`<windows.h>`（Linux 大小写敏感）、`crc.cpp` 指针按 `(long)` 截断→`uintptr_t`、`RKLog.cpp` 缺 `localtime_r`→`localtime` 包装。
6. **WinUSB 类型需要构建期 WDK（重要）**：libwdi 在 `WDK_DIR` 未定义时
   `wdi_is_driver_supported(WDI_WINUSB)` 直接返回 FALSE（`libwdi.c`），`wdi-simple`
   无论 `-t 0/1/2/3` 都会退化为 **CDC/usbser** INF。Linux 交叉构建没有 WDK，因此
   当前 `bin/wdi-simple.exe` **无法绑定 WinUSB**（2026-11-05 实测：装出 usbser，
   `spd_dump` 报 `libusb_open_device failed`）。要恢复该能力需在 Windows+WDK 环境
   构建（configure 时指定 `WDK_DIR`），或改用 Zadig/厂商驱动。

## 手动重建单个组件

各组件构建日志在 `bin/build/*.log`。如需更换上游（RKT_REPO/RKT_COMMIT、LIBWDI_REPO/LIBWDI_COMMIT、LIBUSB_URL/LIBUSB_MD5 环境变量），务必回填本文件固定版本记录，保持溯源完整。
