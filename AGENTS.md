# AGENTS.md — OpenHarmony 通知子系统（ANS）

适用范围：本文件是本仓库（通知子系统，ANS）根级 Agent 指导，适用于仓库内所有目录的编码任务。

## 1. 代码地图

本仓库实现 OpenHarmony 通知子系统（ANS, Advanced Notification Service），核心职责是为应用提供通知发布、订阅、管理能力，并支持跨设备分布式通知同步。最重要的架构边界是**客户端 SDK 与服务端通过 IPC 通信，客户端不持有业务状态**。

### 关键区域

- `interfaces/inner_api/`：公共 C++ API 头文件（`NotificationHelper` 入口类 + 全部数据模型类），所有 C++ 消费者依赖此层，变更影响面最大
- `interfaces/kits/napi/`：ArkTS NAPI 绑定，供 ArkTS 应用使用
- `interfaces/ndk/`：NDK 纯 C 接口，供原生 C 应用使用
- `frameworks/ans/`：IPC 接口定义（IDL 文件）+ 数据模型 Parcelable 实现 + `NotificationHelper` 转发层
- `frameworks/core/`：客户端 SDK 核心逻辑（`AnsNotification` 封装 IPC 调用、连接管理、订阅监听）
- `frameworks/core/common/`：公共基础设施（日志、错误码、常量、权限定义），被 `frameworks/ans` 和 `frameworks/core` 共同依赖，修改影响面大
- `frameworks/js/`：动态 ArkTS 与 C++ 绑定
- `frameworks/ets/`：静态 ArkTS 与 C++ 绑定（与 `frameworks/js` 功能一致，为提升运行效率的演进方案，两套机制均需维护）
- `frameworks/extension/`：三方通知订阅扩展 SDK（基于 ExtensionAbility 机制）
- `frameworks/reminder/`：代理提醒客户端 SDK（`IReminderAgentService.idl` 等 IPC 接口定义 + `ReminderHelper` + `ReminderRequest` 数据模型：闹钟/日历/计时器）
- `frameworks/reminder_ani/`：代理提醒 ArkTS 静态绑定（Taihe/ANI，`ohos.reminderAgentManager`）
- `frameworks/cj/`：仓颉语言 FFI 绑定（`notification_manager_ffi`，向仓颉应用暴露通知能力）
- `services/ans/`：通知服务核心（SystemAbility 服务端，处理发布、订阅、偏好设置、勿扰、角标等全部业务逻辑）
- `services/reminder/`：代理提醒服务端（SystemAbility 3204，提醒的发布/存储/触发调度，触发后经 `NotificationHelper` 转为通知）
- `services/distributed/`：分布式通知服务（跨设备通知同步，基于软总线通信）
- `services/domain/` + `services/infrastructure/`：DDD 风格的领域层与基础设施层（较新架构，封装外部依赖适配器）
- `services/dialog_ui/`：通知弹窗 UI（独立 ArkTS 应用）
- `test/`：`unittest/`（单元测试）、`fuzztest/`（模糊测试）、`systemtest/`（系统测试）、`bechmarktest/`（性能测试）
- `tools/`：开发工具（`dump/` 调试命令、`ohos-notificationManager/`）
- `notification.gni`：全部特性开关（`declare_args()`）定义，新增特性先看这里

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 公共 API 变更 | `interfaces/inner_api/` → `frameworks/ans/src/`（实现）→ `interfaces/kits/napi/`（ArkTS 绑定）→ `interfaces/ndk/`（NDK 绑定） |
| 通知发布/取消/查询逻辑 | `services/ans/src/advanced_notification_manager/` + `services/ans/src/advanced_notification_publish/` |
| 发布过滤器/Slot 判定 | `services/ans/include/notification_filter.h` + `services/ans/src/notification_slot_filter.cpp` |
| 数据模型序列化 | `frameworks/ans/src/notification_*.cpp`（Parcelable 实现） |
| 客户端 SDK 行为 | `frameworks/core/src/ans_notification.cpp`（IPC 客户端核心） |
| 订阅管理 | `services/ans/src/notification_subscriber_manager.cpp` + `services/ans/src/advanced_notification_subscriber_service.cpp` |
| 分布式通知同步 | `services/distributed/src/`（`DistributedNotificationManager` + `soft_bus/`） |
| 三方订阅扩展 | `frameworks/extension/` |
| 代理提醒（reminder） | `frameworks/reminder/`（客户端 SDK + IDL）→ `frameworks/reminder_ani/`（ArkTS 绑定）→ `services/reminder/`（服务端 SA 3204） |
| 偏好设置/持久化 | `services/ans/src/notification_preferences*.cpp` + `services/distributed/src/distributed_preferences*.cpp` |
| 勿扰模式 | `services/ans/src/disturb_manager/` |
| 角标管理 | `services/ans/src/badge_manager/` |
| DFX/打点事件 | 根目录 `hisysevent.yaml` + `hisysevent_notification_ue.yaml` |
| 条件编译特性 | `notification.gni`（特性开关定义） |
| 新增/修改测试 | 对应模块的 `test/unittest/` 目录 |

### 架构分层

```
应用层
  ├─ ArkTS 应用 → interfaces/kits/napi (NAPI 绑定)
  │                 ├─ frameworks/js  (动态 ArkTS 绑定)
  │                 └─ frameworks/ets (静态 ArkTS 绑定)
  ├─ C++ 应用/系统组件 → interfaces/inner_api (完整 C++ API)
  ├─ 原生 C 应用 → interfaces/ndk (精简 C API)
  └─ 仓颉应用 → frameworks/cj (FFI 绑定)
          ↓
客户端 SDK
  NotificationHelper (frameworks/ans/src, 公共入口, 单例转发)
    → AnsNotification (frameworks/core, IPC 客户端逻辑 + 连接管理)
      → IAnsManager proxy (frameworks/ans, IDL 生成的 IPC 接口)
          ↓ IPC
服务端
  AdvancedNotificationServiceAbility (services/ans, SystemAbility 入口)
    → AdvancedNotificationService (核心业务逻辑, 继承 AnsManagerStub)
      ├─ 发布流程 (advanced_notification_manager/ + advanced_notification_publish/)
      ├─ 订阅管理 (subscriber_manager)
      ├─ 偏好/勿扰/角标/优先级...
      ├─ 分布式同步 → DistributedNotificationManager (services/distributed)
      │                 └─ 软总线通信 (soft_bus)
      └─ 领域隔离 → services/domain + services/infrastructure (DDD)

代理提醒（并行链路, 勿与通知发布流程混淆）
  ReminderHelper (frameworks/reminder, 客户端 SDK)
    → IReminderAgentService proxy (frameworks/reminder, IDL 生成)
        ↓ IPC
  ReminderAgentServiceAbility (services/reminder, SystemAbility 3204)
    → 提醒存储/触发调度 → 到点后经 NotificationHelper 转为通知发布
  ArkTS 侧另经 frameworks/reminder_ani (Taihe/ANI 静态绑定) 接入
```

## 2. 知识路由

在规划或编辑前，先对任务分类，读取对应的代码路径和文档。

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 公共 API 新增/修改 | `interfaces/inner_api/` 头文件 + `frameworks/ans/src/` 实现 + `interfaces/kits/napi/` ArkTS 绑定 + 对应 `*.map` 版本脚本 |
| IPC 接口变更 | `frameworks/ans/*.idl` + `frameworks/ans/src/` proxy/stub 实现 |
| 通知发布流程变更 | `services/ans/src/advanced_notification_publish/` + `services/ans/src/advanced_notification_manager/` |
| 分布式通知变更 | `services/distributed/` + `notification.gni` 中分布式相关特性开关 |
| 权限/安全变更 | `frameworks/core/common/include/ans_permission_def.h` + `services/ans/include/access_token_helper.h` + `services/ans/include/permission_filter.h` |
| 偏好设置/持久化变更 | `services/ans/src/notification_preferences*.cpp` + `services/infrastructure/external_adapter/rdb/` + `services/domain/settings/rdb_mgr_repo/` |
| DFX/事件定义变更 | 根目录 `hisysevent.yaml` + `hisysevent_notification_ue.yaml` + `services/ans/include/event_report.h` |
| 代理提醒变更 | `frameworks/reminder/*.idl` + `frameworks/reminder/src/`（客户端 SDK）+ `frameworks/reminder_ani/`（ArkTS 绑定）+ `services/reminder/`（服务端；注意其通过 `NotificationHelper` 与通知服务联动） |
| 新增特性 | `notification.gni` 添加特性开关 → 条件编译包裹代码 |
| 新增/修改测试 | 对应模块 `test/unittest/` 目录 + 对应 `BUILD.gn`（单测 target 定义在 `test/BUILD.gn`） |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `frameworks/core/common/` | 公共基础设施层，被 `frameworks/ans` 和 `frameworks/core` 共同依赖，修改影响面大 |
| `interfaces/inner_api/` | 所有 C++ 消费者的 API 头文件，需同步检查 NAPI 绑定和 NDK 接口 |
| `frameworks/ans/*.idl` | IDL 文件变更会触发 proxy/stub 代码重新生成 |
| `services/ans/include/advanced_notification_service.h` | 服务端核心类（2700+ 行），修改前需理解发布/订阅/管理三大流程 |
| `services/distributed/soft_bus/` | 软总线通信层，修改需理解分布式设备发现、订阅、发布协议 |
| `frameworks/js/` 或 `frameworks/ets/` | 两套 ArkTS 绑定功能一致，修改一套时检查另一套是否需要同步 |
| `test/` | 测试 target 汇总在 `test/BUILD.gn`（`distributed_notification_service_unit_test` / `distributed_notification_service_fuzz_test`） |

### Vocabulary-based routing

当任务、issue、日志、API 名称中出现以下术语时，先理解其含义和风险再动手：

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| ANS | Advanced Notification Service，本子系统简称 | 本文件 |
| Slot / 渠道 | 通知渠道，控制该类通知的默认提醒方式（声音、振动、角标等）。修改 Slot 逻辑影响所有使用该渠道的通知 | `interfaces/inner_api/notification_slot.h` + `services/ans/include/notification_slot_filter.h` |
| LiveView / 实况 | 一种支持实时更新的动态通知类型，有独立的发布流程和订阅管理 | `services/ans/src/advanced_notification_publish/live_publish_process.cpp` + `services/ans/src/system_live_view/` |
| DND / 勿扰 | Do Not Disturb，勿扰模式，控制通知是否静默 | `services/ans/src/disturb_manager/` + `interfaces/inner_api/notification_do_not_disturb_date.h` |
| 特性开关 | `notification.gni` 中的 `declare_args()` 控制条件编译 | `notification.gni` |
| ExtensionAbility | 三方扩展能力框架 | `frameworks/extension/` |
| 代理提醒 / Reminder | 定时提醒能力（闹钟/日历/计时器），到点后由服务端转为通知发布；有独立客户端 SDK（`ReminderHelper`）与服务端 SA 3204，勿与普通通知发布流程混淆 | `frameworks/reminder/` + `services/reminder/` |

### 编辑前必做声明

开始编辑任何代码前，先在回复中声明以下四项，缺一不可：

1. 任务分类（对应上表哪一行）
2. 已读取的代码路径和文档
3. 发现的约束（本文件第 3 节中适用的条目）
4. 是否需要同步修改其他层（如 API 变更需同步 NAPI/NDK、js/ets 两套绑定）

## 3. 约束边界

### 架构不变量

- 客户端 SDK（`frameworks/`）不持有业务状态，所有业务逻辑在服务端（`services/`）执行
- 公共 API 表达稳定的能力意图，不暴露内部实现细节
- 权限校验必须在能力入口（服务端）完成，不能仅依赖客户端
- 所有跨进程传输的数据模型必须实现 `Parcelable`（`Marshalling` / `Unmarshalling`）
- `frameworks/core/common/` 是公共基础设施，被多层依赖，修改需评估全局影响
- 分布式通知必须处理离线、重连、版本不匹配、授权变更场景
- DFX（日志、打点、错误码）必须观测业务关键状态变更

### 禁止事项

- 不要修改公共 API 签名、错误码、权限行为或生命周期语义，除非任务明确要求
- 不要为通过测试而删除日志、事件、错误码或诊断信息
- 不要绕过现有的 DFX、安全、兼容性检查
- 不要直接修改 IDL 生成的 proxy/stub 代码，应修改 `.idl` 源文件后重新生成
- 不要在 `frameworks/js/` 和 `frameworks/ets/` 中只改一套而忽略另一套（两者功能一致）
- 不要引入新的生产依赖而不经过确认
- 不要修改 `*.map` 版本脚本中已有符号的可见性

### 需确认后再修改

- 公共 API 签名变更（需确认兼容性影响和版本策略）
- RDB 持久化 schema 变更（需确认跨版本升级兼容性）
- 分布式协议字段变更（需确认跨设备版本兼容）
- 新增外部依赖（需确认许可证和包大小影响）

### 已知陷阱与常见失败模式

- `sptr` 不是 `std::shared_ptr`：引用计数语义不同，不要混用或用 `std::shared_ptr` 包装 `sptr` 对象
- IDL 生成代码不可手改：`IAnsManager.idl` 等变更后 proxy/stub 由工具重新生成，手改会被覆盖
- 序列化字段顺序即兼容性契约：`Marshalling`/`Unmarshalling` 新增字段必须追加在末尾，且需考虑新旧版本互访
- 两套 ArkTS 绑定（`frameworks/js/` + `frameworks/ets/`）容易漏改一套，提交前必须交叉检查
- 新增代码路径忘记包特性开关：分布式/LiveView/角标等功能受 `notification.gni` 开关控制，直接写死会破坏可裁剪性
- 服务端类按功能拆分在 `services/ans/src/` 多个子目录（如勿扰逻辑在 `disturb_manager/` 而非主类文件），仅 grep 主文件会漏改
- 测试中的 `sleep` 等待不可靠且有超时上限约束，优先使用条件等待（参考 `docs/features/unit-test-sleep-optimization`）

## 4. 验证闭环

### 最小验证

```bash
# 构建整个通知子系统（从 OpenHarmony 根目录执行）
./build.sh --product-name rk3568 --build-target distributed_notification_service

# 构建全部单元测试
./build.sh --product-name rk3568 --build-target distributed_notification_service_unit_test

# 构建全部模糊测试
./build.sh --product-name rk3568 --build-target distributed_notification_service_fuzz_test
```

代码风格遵循 OpenHarmony 根目录 `.clang-format`（CI 门禁检查），本仓无独立 lint 脚本；提交前可用 `.opencode/skills/pre-commit-review` 做静态检视。

### 分任务验证

| 变更类型 | 必须验证 |
|---|---|
| 公共 API 变更 | 最小验证 + `*.map` 中新符号可见性正确 + NAPI/NDK 绑定编译通过 |
| IPC 接口变更 | IDL 重新生成 proxy/stub 后编译通过 + 序列化新旧行为兼容 |
| 服务端业务逻辑 | 最小验证 + 新增/更新对应 `test/unittest/` 用例 |
| 客户端 SDK | 最小验证 + 连接管理/重连场景不回归 |
| 分布式特性 | 至少一种特性开关组合（开/关）下编译通过 |
| 新增测试 | 对应 `BUILD.gn` target 编译通过 |

### Done 定义

- 构建通过（子系统 + 单元测试 + 模糊测试）
- 无新增编译警告
- 变更范围与任务要求一致（无顺手修改无关文件）

### 最终回复要求

任务完成回复必须包含：

1. 变更文件清单（新增/修改/删除）
2. 执行过的验证命令及结果（通过/失败/跳过）
3. 未执行的验证项及原因

### 无法验证时

如果构建环境不可用，不要声称已完成验证。在最终回复中列出应执行的命令、预期结果，并明确标注"未验证"。
