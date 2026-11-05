---
name: device-test
description: "设备端测试统一入口（服务器编排，反向隧道遥控 Windows 执行——服务器不连接设备）。主流程三步：①同步检查（编译产物与设备 .so md5 对比决定是否刷机）→ ②刷机（识别设备类型分发：wukong100/Unisoc 默认走官方 CmdDloader（PAC，自动进下载模式+刷完自动复位），可选 spd_dump，RK3568/Rockchip 走 rkdeveloptool，全在 Windows 侧执行）→ ③测试（push+run 隧道批量执行 / run_tdd 框架路径）。Trigger: 跑单元测试, 验证测试, 推送测试, 板上验证, 跑板子, 刷机, 同步检查, TDD, ACTS, gtest_filter, unittest, moduletest, fuzztest, benchmark, 单测, 部件测试, verify, check_sync, ohos-board-test。"
---

# 设备端测试与刷机（服务器 ←反向隧道→ Windows 执行）

## 总体架构与主流程

```
[服务器: 模型服务/AI + 编译产物] ←──反向隧道(SSH, 控制通道)──→ [Windows: 板(USB) + hdc + 刷机工具]
                                                                            ↑ USB 数据通道
```

**板子常驻 Windows 侧；服务器不连接设备**——所有设备访问（hdc/刷机）一律经隧道在
Windows 侧执行。本环境服务器上存在的 `/usr/local/bin/hdc` 包装脚本（经 10179 端口
转发到 Windows hdc server）是**环境自带设施，不属于本架构**，skill 不依赖它。

### 主流程三步（入口：`verify.sh <module>`）

```
① 同步检查   test/check_sync.sh
   编译产物(packages/phone 镜像内容) vs 设备 .so 的 md5 对比
   → 已同步跳到③ / 不一致进入②
② 刷机      flash/flash.sh（识别设备类型 → 分发单设备模块）
   模块内置环境三查(工具动态发现/驱动/镜像) → 传输镜像 → Windows 侧执行 → 等设备回来
   wukong100 全自动: hdc shell reboot autodloader 进下载 → CmdDloader -pac <pac>
                    → ResearchDownload.ini Reset=1 自动复位 → 等 /system 就绪
③ 测试      push+run（隧道批量执行）或 run_tdd（框架路径，报告回收）
```

```bash
# 首次使用：刷机环境自检（缺工具/驱动时会打印可照抄的两条准备路线）
flash/flash.sh wukong100 --check-env

# 没有任何厂商刷机包？先构建并部署仓库自带工具（注意：WinUSB 绑定当前不可用，见下）
flash/flash.sh wukong100 --bootstrap

# 预演（不刷不传，看完整计划）
verify.sh distributed_notification_service

# 自动刷机 + 测试（主流程全串联）
verify.sh distributed_notification_service --flash-if-needed

# 只查同步 / 只刷机 / 跳过测试
test/check_sync.sh distributed_notification_service        # 退出码 0=同步 1=需刷机
flash/flash.sh                                            # 需交互确认，--dry-run 预演
verify.sh <module> --skip-test --flash-if-needed
```

## 环境与配置（唯一规则表）

优先级：**环境变量 > env.conf > 自动探测/推导**。配置文件 `~/.config/ohos-board-test/env.conf`
由 `test/tunnel/init.sh` 向导生成（两链路共用）。

| 配置 | 环境变量 | env.conf | 自动行为 |
|---|---|---|---|
| 产品名 | `OH_PRODUCT` | `PRODUCT_NAME` | 探测 out/ 下含 `packages/phone/images` 的板级产品（排除 sdk 构建）；多个并存时报错列候选 |
| Windows 用户 | — | `WIN_USER` | 从隧道连接记录推导（`/tmp/opencode/tunnel_status.txt` 的 `TUNNEL_UP <用户名>`，反映当前实际连接） |
| Windows 工作目录 | — | `WIN_DIR` | 按 WIN_USER 重算；与用户名不符的坏值自动纠正 |
| 刷机工具位置 | — | `FLASH_TOOL_DIR` | 动态发现探测链：登记位置 → `$WIN_DIR\bin` → PATH → 用户目录扫描 |
| 隧道端口 | `TUNNEL_PORT` | — | 默认 12222 |
| hdc（Windows 侧） | — | `HDC_EXE`/`TOOLCHAINS_DIR` | init 向导探测完整路径（本环境 `AppData\Local\OpenHarmony\Sdk\<ver>\toolchains`） |

环境层唯一正本：`lib/env.sh`（全部探测/推导/隧道封装/动态发现函数）。

## ① 同步检查（test/check_sync.sh）

- **基准**：`out/<product>/packages/phone/{system,sys_prod,vendor}/lib*/` 的 `.so`
  ——这是**刷机后设备上的真实文件**（不用编译中间产物，两者有 strip 差异直接比对会误报）；
  packages 与设备 rootfs 路径镜像对应，按镜像路径直查设备 md5
- **范围**：`check_sync.sh <module>`（模块的 .so 清单）或 `--all`（全系统）
- **链路（唯一：隧道）**：所有设备访问经 `win_hdc`/`win_hdc_shell`（Windows 侧 hdc）批量执行
- **退出码**：0=已同步；1=需刷机；2=错误。供 verify.sh / CI 决策

## ② 刷机（flash/）

**原则**：刷机域按设备分层，每模块只针对一个设备、自包含零泛化；`flash.sh`
统一入口按镜像特征识别设备类型并分发。刷机全部经隧道在 Windows 侧执行。

| 设备 | 识别特征 | 模块 | 工具 |
|---|---|---|---|
| **wukong100**（Unisoc UIS7885/UMS9620, 64 位） | images 含 `*.pac` | `flash/wukong100/` | `spd_dump.exe`（Unlicense，源码构建） |
| **RK3568**（Rockchip, 32 位） | images 含 `parameter.txt` | `flash/rk3568/` | `rkdeveloptool.exe` |

```bash
flash/flash.sh [product] --dry-run    # 预演：完整操作计划（分区写入/擦除清单+FDL地址）
flash/flash.sh [product] --yes        # 执行（verify.sh 自动化时自动加 --yes）
```

**环境三查（每模块刷机前自动执行）**：工具（动态发现探测链）→ 驱动（pnputil 查
VID：2207/Rockchip、1782/SPRD）→ 镜像。任一不满足时打印准备步骤并指向
**`references/flash-env.md`** 对应小节（§0 通用部署 / §1 RK3568 / §2 wukong100 / §3 故障对照），
按提示准备后重试即可。

**wukong100 模块要点**：
- 数据零额外资产：镜像取 `out/<product>/packages/phone/images/`，FDL 地址与角色→分区
  映射运行时解析自 `device/soc/unisoc/p7885/pac/ImageFiles/`（flash.cfg + SoC XML），
  实测 FDL1 `0x65000800` / FDL2 `0xB4FFFE00`
- **prodnv 默认不写**（保留板上 NV；官方 NvBackup 编排不可复刻；重置加 `--include-nv`）
- **SPL 变体互斥**（防砖关键）：官方 pac 携带 emmc/ufs 两变体同写 splloader，选错必砖；
  设备在线自动探测存储类型（UFS: /sys/block 见 `sd*`；eMMC: 见 `mmcblk*`），设备已关机时
  须 `--spl=emmc|ufs` 指定
- 镜像 md5 增量传输（变更文件才传），执行 `spd_dump.exe` 于 Windows 侧 staging 目录

**RK3568 模块要点**：镜像 tar 传输（排除 `eng_system.img`）→ 设备在线则软进 Loader
（`reboot loader`）→ 调 `flash_rk3568.bat [镜像目录] [工具路径]`（分区地址以同源
parameter.txt 为准，单一来源）。

## ③ 测试（test/，全部经隧道执行——服务器不连接设备）

| 入口 | 说明 |
|---|---|
| `test/push_module_tests.sh` + `test/run_module_tests.sh` | 精细控制（增量推送/gtest_filter/单二进制/崩溃计数），**服务器编排、Windows 侧 hdc 执行** |
| `test/tunnel/run_tdd.sh` 等 | TDD/ACTS 框架路径（developer_test 报告回收），需要正式报告时用 |

### push_module_tests.sh（隧道批量传输设计）

```bash
test/push_module_tests.sh <module> [--type=unittest|moduletest|fuzztest|benchmark|all] \
  [--incremental] [--libs-only] [--tests-only] [--lib=<name>] [--remount]
```

- 全流程仅 ~10 次隧道往返：收集清单 → **一次批量** find 探测板上实际路径 → **一次批量** stat 增量判定 → tar+scp 到 Windows staging → **一次 win_ssh for 循环**批量 file send → 分块（8 段/次）备份与安装 → **分块批量** md5 校验 → 清理
- **新库落位按包镜像树**（`out/<product>/packages/phone/{system,vendor}/lib*` 镜像规则，与 check_sync 一致），找不到才落探测目录
- **覆盖采用 rm-then-cp**：被运行中进程 mmap 的库裸 cp 会 ETXTBSY 静默失败；rm 后 cp 新建 inode 不受影响（覆盖前已备份 `/data/backup_*`）
- 安装后**逐目标 md5 校验，缺失即计失败并退出码非 0**（杜绝"删了没装"被静默漏计）
- 诊断日志：`/tmp/opencode/push_debug.log`（每次传输确认数/源抽查/分块执行）

### run_module_tests.sh

```bash
test/run_module_tests.sh <module> [--type=...] [--gtest-filter=<p>] [--timeout=<s>] \
  [--verbose] [--list] [--list-tests] [--binary=<name>] [log_file]
```

- `LD_LIBRARY_PATH` 按设备架构自动探测（aarch64→`/system/lib64[/platformsdk]`）
- 通过率分母纳入崩溃/超时；退出码 0=全过 1=有失败 2=用法错误
- **隧道设备命令关键约束**：设备命令经 `win_hdc_shell` **整体加引号**下发（cmd 引号内不解析
  `2>/dev/null`/`&&`，否则被 cmd 截获致整条命令中止）；设备命令内**禁用双引号**（会破坏
  wrapper 引号配对），路径无空格裸写、含空格用单引号

### find_module_libs.sh（纯本地诊断，不碰设备）

```bash
test/find_module_libs.sh <module> [--symbol <name>]     # 模块库与 NEEDED 依赖诊断
```

### 隧道链路工具（test/tunnel/）

| 工具 | 用途 |
|---|---|
| `init.sh` | 接入向导：密钥/配置生成/渲染 Windows 安装脚本/探测 hdc+旧目录沿用 |
| `check.sh` | 环境自检（隧道/板子/Python） |
| `run_tdd.sh <part> [target]` | TDD：编译→组包→推送→远程执行→报告回收 |
| `run_acts.sh <part> [module]` | ACTS 兼容性（xts 编译三要素已内置） |
| `push_so.sh <part>` | 部件 so 增量推送（路径探测+备份+md5 校验） |
| `collect_report.sh [tdd\|acts]` | 手动回收最新报告 |

## 设备类型适用范围

| 能力 | 板型 |
|---|---|
| 测试推送/运行（check_sync/push/run/tunnel 全部） | **设备无关**（已在 64 位 Unisoc wukong100 与 32 位 RK3568 双板验证；架构/库目录自动探测） |
| 刷机 wukong100 模块 | 仅 Unisoc（UIS7885/UMS9620） |
| 刷机 rk3568 模块 | 仅 Rockchip（RK3568 等） |

团队双板环境：**wukong100**（revoview/Unisoc UMS9620，8 核 64 位）与 **RK3568**
（hihope，32 位）。新设备接入：`flash/` 下新建单设备模块目录 + `flash.sh` 登记一行识别特征，
测试域零改动。

## 诊断与故障

- 测试故障手册：`references/common-failures.md`（symbol not found / 崩溃 / 超时等）
- 刷机环境故障对照：`references/flash-env.md §3`
- **推跨部件系统库导致开不了机**是已知红线事故：板子系统与工作区不同源时单独推
  其他部件的库（如 libwant）会破坏符号链配套——正确做法是走刷机（`--flash-if-needed`）

## 新同事接入

1. 克隆本仓库（skill 随仓库分发；刷机工具首次使用由 `bin/ensure_bin.sh` 源码构建）
2. `test/tunnel/init.sh`——生成专属密钥/配置、渲染 Windows 安装脚本；在其 Windows
   管理员 PowerShell 执行向导给出的命令（OpenSSH Server/公钥/隧道常驻）
3. 回服务器按回车 → 自动探测 hdc/python/旧目录沿用 → check 全绿即就绪
4. 刷机环境按 `references/flash-env.md` 准备（环境三查会自动提示缺什么）

## 附录

### 工具链自举（bin/）

`bin/ensure_bin.sh` 从上游源码构建全部 Windows 侧刷机工具（**bin/ 不携带二进制，合规**）：
`rkdeveloptool.exe`、`libusb-1.0.dll`、`wdi-simple.exe`（驱动全自动安装，libwdi 引擎）、
`spd_dump.exe`。固定版本/补丁/许可证/构建适配记录见 `bin/BUILD.md`。

### Windows 侧目录约定（脚本自动维护）

```
C:\Users\<user>\board-test\        （新约定；旧部署 C:\Users\<user>\rk3568\ 会被 init.sh 探测沿用）
├── bin\        刷机工具（动态发现约定位置；也可 env.conf 登记 FLASH_TOOL_DIR）
├── flash\<device>\  刷机镜像 staging（wukong100: md5 增量；rk3568: tar 解包）
├── Test\       developer_test 框架（run_tdd 组包）
├── acts\  reports\  tmp\          ACTS 套件 / 报告 / 传输中转
```

- 板：wukong100（64 位 aarch64，UFS 存储）与 RK3568（32 位）双板环境
- 密钥 `~/.ssh/board_win`（旧名 rk3568_win 兼容）；免密依赖 Windows 公钥装入服务器 authorized_keys
- 交付框架 developer_test/xdevice：源码 `test/testfwk/`，运行副本 `<工作区>/board-test_delivery/`（缺失自动重建）
- 报告回收策略：只回传本次新增报告（快照差分），历史留 Windows 侧

---

# Feature 工作流集成（VERIFY 阶段契约）

本 skill 被 `Feature-Verify-SubAgent` 在 Build 阶段编译通过后调用。

- **主入口**：`verify.sh <module>`——同步检查 →（`--flash-if-needed` 则刷机）→ 测试
- **链路**：唯一隧道链路（服务器不连接设备）；隧道不可达/无设备时报告并退出
  VERIFY_SKIPPED（`skip_reason: no_device`），不阻塞流程
- **默认测试类型**：unittest + moduletest（fuzztest/benchmark 仅当 plan.md 的
  `test_commands` 显式包含）
- **退出码语义**：verify.sh 0=同步且测试通过；1=需刷机（不加 --flash-if-needed 时）/
  测试失败/刷机失败；2=用法错误。push 退出码 1=环境问题；run 退出码 1=测试失败或前置错误
- **失败任务定位**：失败二进制名 → plan.md 中 task 的 `test_commands` 含该二进制名；
  失败 TestSuite 名 → task 的 `files_write` 中测试文件路径；无法匹配 → `unmapped` 建议 `human_review`
- **产物**：调用方写 `{kb_dir}/verify-log.md`（环境信息/同步检查结果/刷机记录/各类型计数/失败诊断/日志路径）
