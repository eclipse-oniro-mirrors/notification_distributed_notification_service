# 刷机环境准备（Windows 侧）

> 刷机全部经反向隧道在 **Windows 侧**执行（板子接 Windows 机的 USB）。各刷机模块
> 执行前会自动做**环境三查**（工具/驱动/镜像），不满足时打印的准备步骤均指向本文
> 对应小节——照抄执行即可恢复。

## §0 通用：工具链构建与部署

> **第一次用、机器上还没有刷机环境？** 先跑自检，它会逐项报告并给出可复制执行的准备步骤：
> `bash flash/flash.sh wukong100 --check-env`
>
> 两条路线任选其一：
> - **方案A（推荐，需厂商包）**：解压展锐 ResearchDownload 工具包 → `init.sh` 自动发现，
>   或 `echo 'FLASH_TOOL_DIR="D:/.../SPD_Research_Tool_XXX"' >> ~/.config/ohos-board-test/env.conf`
> - **方案B（无厂商包，暂不可用）**：`bash flash/flash.sh wukong100 --bootstrap` 可自动构建并
>   部署 `spd_dump.exe`+`libusb-1.0.dll`+`wdi-simple.exe`，但——
>   ⚠ **仓库自带的 `wdi-simple.exe` 无法绑定 WinUSB**：libwdi 构建时没有 WDK
>   （`config.h` 为 `#undef WDK_DIR`），`wdi_is_driver_supported(WDI_WINUSB)` 返回 FALSE，
>   无论 `-t 0/1/2/3` 都只生成 CDC/usbser INF，`spd_dump` 必然报 `libusb_open_device failed`
>   （2026-11-05 实测确认）。同一缺陷也影响 RK3568 的 `install_winusb.bat`。
>
> **没有厂商包时的临时可行路径**：用公开工具 Zadig（https://zadig.akeo.ie）给
> `VID_1782/PID_4D00` 安装 WinUSB 驱动，再 `bash flash/flash.sh wukong100 --tool=spd_dump --spl=ufs --yes`。
>
> **长期修复**：在有 WDK 的 Windows 环境重建 libwdi/wdi-simple（`ensure_bin.sh` 需设置
> `WDK_DIR`），使 WinUSB 类型被真正嵌入。

工具链**不入库**，由 `bin/ensure_bin.sh` 在服务器从上游源码构建（固定版本与溯源见
`bin/BUILD.md`）：

```bash
bash bin/ensure_bin.sh          # 全部（幂等）；--only=<组件> 可单建
# 产物: rkdeveloptool.exe  libusb-1.0.dll  wdi-simple.exe  spd_dump.exe
```

**部署到 Windows**（约定位置 `$WIN_DIR\bin\`，即 `C:\Users\<user>\board-test\bin\`；
旧部署为 `C:\Users\<user>\rk3568\bin\`，两者皆可）：

```bash
scp -P 12222 bin/spd_dump.exe bin/rkdeveloptool.exe bin/wdi-simple.exe bin/libusb-1.0.dll \
    <win>:$WIN_DIR/bin/
```

**位置登记（可选）**：工具放在其他位置时，在 `~/.config/ohos-board-test/env.conf` 写：

```
FLASH_TOOL_DIR="C:/Users/<user>/mytools"
```

**动态发现顺序**（刷机时自动探测，找到即用，全部未命中才报缺工具）：

1. env.conf 登记位置（`FLASH_TOOL_DIR`）
2. 约定目录（`$WIN_DIR\bin\`）
3. Windows PATH（`where xxx.exe`）
4. 常见目录快速扫描（Desktop/Downloads/WIN_DIR，限时；自定义位置请登记 `FLASH_TOOL_DIR`）

## §1 RK3568（Rockchip）

| 项 | 准备 | 验证 |
|---|---|---|
| 工具 | §0 构建 + 部署 `rkdeveloptool.exe` + `libusb-1.0.dll`（**须同目录**） | 环境三查/`where rkdeveloptool.exe` |
| 驱动 | Windows 管理员执行 `flash/rk3568/install_winusb.bat`（wdi-simple 全自动：生成 INF + 自签证书 + 导入信任链 + 安装；无需 SDK/测试签名/重启）⚠ 当前 `bin/wdi-simple.exe` 因构建无 WDK 只能生成 CDC/usbser（见 §0 方案B 说明），该脚本暂不可用；请改用厂商 Loader 驱动或 Zadig 绑定 WinUSB | 驱动库含 VID_2207（`findstr /m /i "VID_2207" C:\Windows\INF\oem*.inf`） |
| 镜像 | 编排脚本自动传输（tar 排除 `eng_system.img`）；手动时 `scp -P 12222 .../images.tar.gz <win>:...` | 目标目录有 `parameter.txt` + 各分区镜像 |

- **进入 Loader 模式**：设备在线时 `hdc shell "reboot loader"`（编排脚本自动做）；
  系统挂了则物理按键：**按住 RECOVERY 再按 RESET**
- 验证 Loader：`rkdeveloptool.exe ld` 应显示 `Pid=0x350a Loader`
- 执行入口：`flash/flash.sh <product> --yes`（服务器编排）或 Windows 侧直接跑 `flash_rk3568.bat [镜像目录] [工具路径]`

## §2 wukong100（Unisoc UIS7885/UMS9620）

| 项 | 准备 | 验证 |
|---|---|---|
| 工具 | **默认**：展锐官方 `CmdDloader.exe`（ResearchDownload 工具包），在 `env.conf` 登记 `FLASH_TOOL_DIR=<工具目录>`；备选：§0 构建 + 部署 `spd_dump.exe` + `libusb-1.0.dll`（**须同目录**） | 环境三查/`where CmdDloader.exe` |
| 驱动 | 安装 SPD USB 驱动包（`SPD_Driver_R4.20.4201`，展锐官方 U2S 驱动）；或 Zadig 绑定 WinUSB（⚠ 仓库自带 `wdi-simple.exe` 因无 WDK 无法装 WinUSB，见 §0） | 驱动库含 VID_1782（`findstr /m /i "VID_1782" C:\Windows\INF\oem*.inf`） |
| 镜像 | 编排脚本自动传输（md5 增量，仅传变更文件）到 `$WIN_DIR\flash\wukong100\` | 传输日志逐文件 [传输]/[跳过] |

- 数据源零额外资产：镜像取 `out/<product>/packages/phone/images/`，FDL 与角色映射取
  `device/soc/unisoc/p7885/pac/ImageFiles/`（`flash.cfg` + SoC XML，运行时解析）
- **刷机工具路线（默认全自动）**：存在 `*.pac` 时默认 `--tool=cmdloader`——
  ①`hdc shell reboot autodloader` 进下载模式（4~6 秒）→ ②经隧道在 Windows 侧执行
  `CmdDloader.exe -pac <pac>`（走展锐 U2S 串口，**不需要 WinUSB**）→ ③刷完由
  `ResearchDownload.ini` 的 `[Options] Reset=1` 自动复位回系统。
  注意：命令行参数 `-Reset` 在本工具版本中**无效**（`CmdDloader.exe -h` 未列出），
  必须改 ini；`--tool=spd_dump` 仅在设备已绑定 WinUSB 驱动时可用。
  脚本内置 900s 看门狗，超时自动 kill 工具并报错。
- **进入下载模式**（二选一）：
  - 软件方式（系统在线时首选，已实测 6 秒生效）：`hdc shell reboot autodloader`
    （必须拼作 **`autodloader`**——内核 `drivers/spi/spi-sprd-adi.c` 只认这个字符串，
    写成 `autoloader`/`download` 都会落回普通重启；进入后 Windows 侧枚举为
    `VID_1782&PID_4D00`，友好名 `SPRD U2S Diag (COMx)`）
  - 物理方式（系统离线/无法开机时）：**按住三按键一侧的中间键（音量+, VOL+）**
    再接 USB/上电；或上电状态下按住 VOL+ 再按另一侧 RESET
  - 注意：下载模式下设备绑定展锐 U2S 串口驱动，`spd_dump`(libusb) 会报
    `libusb_open_device failed`，此时用官方 `CmdDloader.exe -pac <pac>`
    （走 COM 口，命令行**不要**加 `-Reset`——该参数本版本无效）刷写
- **prodnv 默认不写**（保留板上既有 NV；确需重置加 `--include-nv`）
- **SPL 变体**：设备在线时自动探测存储类型（UFS/eMMC）；设备已关机时须
  `--spl=emmc|ufs` 指定（两个变体写同一分区，选错会砖——见 §3）
- 执行入口：`flash/flash.sh <product>`（服务器编排，`--dry-run` 可预演全部操作计划）

## §3 故障对照

| 症状 | 根因 | 解法 |
|---|---|---|
| `[缺工具] xxx.exe 未找到` | 未构建/未部署/位置未登记 | §0：ensure_bin 构建 → scp 部署 →（非约定位置时）登记 FLASH_TOOL_DIR |
| `[缺驱动] VID_2207 无 WinUSB` | Loader 设备绑定 Rockusb 私有驱动 | §1：管理员跑 install_winusb.bat |
| `[缺驱动] VID_1782 无 SPD 驱动` | 未装 SPD 驱动/WinUSB 未绑定 | §2：装 SPD_Driver 或 wdi-simple 绑定 |
| `rkdeveloptool ld` 无 Loader 设备 | 板子未进 Loader 模式 | §1：reboot loader / 物理按键（RECOVERY+RESET） |
| spd_dump `--wait` 超时无设备 | 板子未进下载模式 | §2：`hdc shell reboot autodloader` 或按住 VOL+ 接 USB |
| spd_dump 打开设备失败（`libusb_open_device failed`） | 下载模式下设备绑定展锐 U2S 串口驱动（`SPRD U2S Diag (COMx)`），libusb 无法打开 | §2：改用官方 `CmdDloader.exe -Reset -pac <pac>`（走 COM 口）；或 wdi-simple 绑定 WinUSB 后再用 spd_dump |
| 刷完 wukong100 起不来（`splloader` 写错变体） | `--spl` 与实际存储不符 | 重刷并确认变体：64 位板多为 UFS（/sys/block 见 sd*），eMMC 见 mmcblk* |
| 刷机后仍提示不同步 | 镜像与产物非同批构建 | 重新编译 → 重跑 ensure 流程（`verify.sh --flash-if-needed`） |
