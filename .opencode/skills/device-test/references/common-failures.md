# 常见测试故障

OpenHarmony 模块测试故障诊断参考。

> **范围说明**: 故障模式（符号缺失、命名空间歧义、错误码体系、Mock 过期、超时、崩溃等）适用于任意 OpenHarmony 模块。文中具体测试名/类名/错误码示例多取自通知子系统（distributed_notification_service），仅为便于阅读，其他模块替换为自身符号即可。

## 快速诊断表

| 错误信息 | 首先排查 | 修复方法 |
|---|---|---|
| `symbol not found` | 缺少或过期的 `.so` | 推送所有模块库 |
| `reference to 'X' is ambiguous` | `using namespace` 遅蔽了类名 | 重新限定命名空间或移除 using |
| `Expected 67108867, got 120001` | 内部错误码与服务错误码不匹配 | 更新测试期望值 |
| `Expected 110001, got 67108877 (TASK_ERR)` | `InnerToService` 未对服务码做幂等处理 | 让服务码范围内直接透传 |
| `Segmentation fault (signal 11)` | 空指针解引用或 mock 未初始化 | 检查 `SetUp()` |
| `Aborted (signal 6)` | `ASSERT_*` 在测试体外使用，或未处理异常 | 检查测试生命周期 |
| `Killed (signal 9)` | 超时或内存不足 | 增加超时或减少测试数据 |
| `No tests run` | `--gtest_filter` 过滤条件过于严格 | 检查过滤模式 |
| `cannot execute binary file` | ARM 二进制在 x86 主机运行 | 通过 hdc 在设备上执行 |
| `Permission denied` | `.so` 缺少 `chmod 644` | 用推送脚本重新推送 |
| `timeout: exec cd: No such file or directory` | `timeout` 无法执行 shell 内建命令 | 用 `sh -c` 包装命令 |

## 1. 运行时重定位/符号错误

**现象**:
```
Error relocating <binary>: <symbol>: symbol not found
```

**原因**: 依赖的 `.so` 未推送到设备，或设备上存在旧版本缺少新符号。

**诊断**:
```bash
# 用 find_module_libs.sh 定位符号
<path-to-skill>/test/find_module_libs.sh <module> --symbol <symbol_name>

# 手动检查
for lib in out/<product>/*<module>*/*.so; do
  llvm-nm -D "$lib" 2>/dev/null | grep -F "<symbol_name>" && echo "^^^ $lib"
done
```

**修复**: 推送包含该符号的库到 `/system/lib/platformsdk/`：
```bash
<path-to-skill>/test/push_module_tests.sh <module> --libs-only
```

**注意**: 测试依赖整个依赖链中的多个库（如 `libans_innerkits.z.so`、`libans.z.so`、`libans_base.z.so`、`libdans.z.so`）。只推送一个不够——需要全部推送。

## 2. 命名空间歧义（`reference to 'Notification' is ambiguous`）

**原因**: 在 `namespace OHOS::SomeSubNs` 中添加 `using namespace OHOS::Notification;` 引入类 `OHOS::Notification::Notification`。`Notification::` 有歧义（命名空间还是类）。

**修复方案**（按优先级）：
1. **保留 `using namespace`**，直接使用裸名：`NotificationSlot` 而非 `Notification::NotificationSlot`。
2. **完全限定**: `OHOS::Notification::NotificationConstant`。
3. **移除 `using namespace`**。

**错误模式**:
```cpp
namespace NotificationSts {
using namespace OHOS::Notification;
Notification::NotificationSlot s;  // 有歧义
```

**正确模式**:
```cpp
namespace NotificationSts {
using namespace OHOS::Notification;
NotificationSlot s;  // 无歧义
```

## 3. 错误码不匹配（`ERR_ANS_*` vs `ERR_ANS_SVC_*` vs 外部码）

三个并存的错误码体系：
- **内部码** (`ans_inner_errors.h`): `ERR_ANS_*` — 基址偏移约 67108866+ (`0x04000003`)
- **服务码** (`ans_service_errors.h`): `ERR_ANS_SVC_*` — 纯整数，如 `110001`、`120001`
- **外部码** (JS/ETS 面向): 如 `ERROR_PERMISSION_DENIED = 201`

**常见故障模式**:

| 测试期望 | 实际返回 | 诊断 |
|---|---|---|
| `ERR_ANS_INVALID_PARAM (67108867)` | `120001 (ERR_ANS_SVC_INVALID_PARAM)` | 服务层返回服务码；测试期望内部码。修复：更新期望值或用 `ServiceErrorToInner()`。 |
| `ERR_ANS_PERMISSION_DENIED` | `ERR_ANS_TASK_ERR` | `InnerToService` 无法反向映射。让其幂等：服务码范围内直接透传。 |

**标准转换层**:
```
IPC 返回 ErrCode → InnerToService(errCode) → ServiceErrorCode → ServiceErrorToInner(svc) → 内部 ErrorCode
```

## 4. Mock 返回值过期

**现象**: 测试期望 `ERR_ANS_SVC_INVALID_PARAM` 但 mock 返回 `ERR_ANS_INVALID_PARAM`。

**修复**: 更新 mock 头文件和实现，引入 `ans_service_errors.h` 并返回服务码。

## 5. 测试队列重置/环境问题

**现象**: 测试单独运行通过，但整个二进制顺序运行时失败。

**可能原因**: 跨测试用例共享全局状态；`TearDown` 中队列重置；Extension wrapper 缓存。

**修复**: 确保 `SetUp()` 重新初始化所有共享状态；避免 mock 中的 `static` 全局变量。

## 6. 测试超时

**现象**: 测试二进制运行超过超时阈值未完成。

**可能原因**: 无限循环；多线程死锁；设备操作极慢。

**诊断**:
```bash
run_module_tests.sh <module> --gtest-filter='<TestClass>.<TestMethod>' --verbose --timeout=30
```

**修复**: 在测试代码中为异步等待添加超时；减少测试数据量。

## 7. 测试崩溃（SIGSEGV / SIGABRT / SIGKILL）

**SIGSEGV (信号 11)** — 空指针解引用或无效内存访问：
- mock 是否在需要非空指针处返回了 `nullptr`？
- `SetUp()` 是否跳过了 `TearDown()` 假定存在的初始化？

**SIGABRT (信号 6)** — `ASSERT_*` 在测试体外使用，或未处理异常：
- 在辅助函数中使用 `ASSERT_*`——它们会调用 `abort()`。
- 生产代码未处理异常。

**SIGKILL (信号 9)** — 进程被外部终止：
- 若非超时：可能 OOM。减少测试数据量。
- `hdc shell dmesg | tail` 查看 OOM killer 消息。

**诊断**:
```bash
run_module_tests.sh <module> --gtest-filter='<TestClass>.<TestMethod>' --verbose --timeout=30
```

## 8. fuzztest 特殊问题

fuzztest 与 unittest/moduletest 运行方式不同：

- **无 GTest 输出**: fuzztest 不产生 `[  PASSED  ]` / `[  FAILED  ]`，只判断是否崩溃
- **运行时间短**: fuzztest 通常几秒内完成，默认超时 60 秒
- **崩溃即失败**: fuzztest 正常退出视为通过，崩溃视为失败

**常见 fuzztest 故障**:
- **立即崩溃**: 输入数据格式错误或 buffer 越界——检查 Fuzz 测试的 `FuzzedDataProvider` 用法
- **卡住不退出**: fuzztest 实现中可能有无限循环——增加超时限制
- **`Error relocating`**: 与 unittest 相同，缺少 `.so`——推送所有模块库

## 9. 设备已知故障

> **⚠ 范围说明**: 下表为 **OpenHarmony 通知子系统（distributed_notification_service）** 在 rk3568 设备上记录的预存故障。其他模块的已知故障请由各模块自行维护到其 `AGENTS.md` 或本地参考文档中，不要回写至本通用 skill。

| 测试 | 已知原因 |
|---|---|
| `voice_extension_wrapper_test` | Extension 动态加载；依赖真实 Extension 进程 |
| `notification_extension_test` | 测试环境中分布式数据库未配置 |
| `reminder_test` (日历/定时器) | 时间相关的边界情况 |
| `notification_config_parse_test` | `/data/local/tmp` 中缺少配置文件 |
| `common_utils_test.AesGcmHelperUnitTest` | AES-GCM 需要加密设备 |
| `notification_preferences_database_test.GetLiveViewEnable` | 跨运行间 DB 状态不匹配 |

这些是**预存故障**，非回归问题。过滤排除：
```bash
run_module_tests.sh <module> --gtest_filter='-<KnownTestClass>*'
```

## 10. 设备上库过期

**现象**: 编译成功，重新推送了库，但测试仍使用旧行为。

**修复**:
```bash
# 验证设备库与本地库匹配
hdc shell "stat -c '%Y %s' /system/lib/platformsdk/<libname>"

# 强制重新推送
push_module_tests.sh <module> --libs-only  # 不带 --incremental
```

## 11. 推送/运行类型不匹配

**现象**: 推送了 unittest 测试到 `/data/local/tmp/<module>_unittest/`，但 `--type=fuzztest` 运行找不到测试。

**原因**: 每种测试类型推送到独立目录。推送和运行时必须使用相同的 `--type`。

**修复**: 确保推送和运行使用相同的 `--type` 参数：
```bash
push_module_tests.sh <module> --type=unittest
run_module_tests.sh <module> --type=unittest
```