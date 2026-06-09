# AGENTS.md — OpenHarmony 通知子系统（ANS）

## 1. 代码地图

本仓库实现 OpenHarmony 通知子系统（ANS, Advanced Notification Service），核心职责是为应用提供通知发布、订阅、管理能力，并支持跨设备分布式通知同步。最重要的架构边界是**客户端 SDK 与服务端通过 IPC 通信，客户端不持有业务状态**。

### 非本项目维护的目录

以下目录由其他团队暂存，不属于本项目维护范围，修改时请跳过：

- `frameworks/cj/`
- `frameworks/reminder/`
- `frameworks/reminder_ani/`
- `services/reminder/`

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
- `services/ans/`：通知服务核心（SystemAbility 服务端，处理发布、订阅、偏好设置、勿扰、角标等全部业务逻辑）
- `services/distributed/`：分布式通知服务（跨设备通知同步，基于软总线通信）
- `services/domain/` + `services/infrastructure/`：DDD 风格的领域层与基础设施层（较新架构，封装外部依赖适配器）
- `services/dialog_ui/`：通知弹窗 UI（独立 ArkTS 应用）
- `tools/`：开发工具（dump 命令）

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 公共 API 变更 | `interfaces/inner_api/` → `frameworks/ans/src/`（实现）→ `interfaces/kits/napi/`（ArkTS 绑定）→ `interfaces/ndk/`（NDK 绑定） |
| 通知发布/取消/查询逻辑 | `services/ans/src/advanced_notification_manager/` + `services/ans/src/advanced_notification_publish/` |
| 数据模型序列化 | `frameworks/ans/src/notification_*.cpp`（Parcelable 实现） |
| 客户端 SDK 行为 | `frameworks/core/src/ans_notification.cpp`（IPC 客户端核心） |
| 分布式通知同步 | `services/distributed/src/`（`DistributedNotificationManager` + `soft_bus/`） |
| 三方订阅扩展 | `frameworks/extension/` |
| 偏好设置/持久化 | `services/ans/src/notification_preferences*.cpp` + `services/distributed/src/distributed_preferences*.cpp` |
| 勿扰模式 | `services/ans/src/disturb_manager/` |
| 角标管理 | `services/ans/src/badge_manager/` |
| 条件编译特性 | `notification.gni`（特性开关定义） |
| 新增/修改测试 | 对应模块的 `test/unittest/` 目录 |

### 架构分层

```
应用层
  ├─ ArkTS 应用 → interfaces/kits/napi (NAPI 绑定)
  │                 ├─ frameworks/js  (动态 ArkTS 绑定)
  │                 └─ frameworks/ets (静态 ArkTS 绑定)
  ├─ C++ 应用/系统组件 → interfaces/inner_api (完整 C++ API)
  └─ 原生 C 应用 → interfaces/ndk (精简 C API)
          ↓
客户端 SDK
  NotificationHelper (frameworks/ans/src, 公共入口, 单例转发)
    → AnsNotification (frameworks/core, IPC 客户端逻辑 + 连接管理)
      → IAnsManager proxy (frameworks/ans, IDL 生成的 IPC 接口)
          ↓ IPC
服务端
  AdvancedNotificationServiceAbility (services/ans, SystemAbility 入口)
    → AdvancedNotificationService (核心业务逻辑, 继承 AnsManagerStub)
      ├─ 发布流程 (publish_process)
      ├─ 订阅管理 (subscriber_manager)
      ├─ 偏好/勿扰/角标/优先级...
      ├─ 分布式同步 → DistributedNotificationManager (services/distributed)
      │                 └─ 软总线通信 (soft_bus)
      └─ 领域隔离 → services/domain + services/infrastructure (DDD)
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
| 偏好设置/持久化变更 | `services/ans/src/notification_preferences*.cpp` + `services/ans/src/notification_rdb_data_mgr.cpp` |
| 新增特性 | `notification.gni` 添加特性开关 → 条件编译包裹代码 |
| 新增/修改测试 | 对应模块 `test/unittest/` 目录 + 对应 `BUILD.gn` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `frameworks/core/common/` | 公共基础设施层，被 `frameworks/ans` 和 `frameworks/core` 共同依赖，修改影响面大 |
| `interfaces/inner_api/` | 所有 C++ 消费者的 API 头文件，需同步检查 NAPI 绑定和 NDK 接口 |
| `frameworks/ans/*.idl` | IDL 文件变更会触发 proxy/stub 代码重新生成 |
| `services/ans/include/advanced_notification_service.h` | 服务端核心类（2700+ 行），修改前需理解发布/订阅/管理三大流程 |
| `services/distributed/soft_bus/` | 软总线通信层，修改需理解分布式设备发现、订阅、发布协议 |
| `frameworks/js/` 或 `frameworks/ets/` | 两套 ArkTS 绑定功能一致，修改一套时检查另一套是否需要同步 |

### Vocabulary-based routing

当任务、issue、日志、API 名称中出现以下术语时，先理解其含义和风险再动手：

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| ANS | Advanced Notification Service，本子系统简称 | 本文件 |
| Slot / 渠道 | 通知渠道，控制该类通知的默认提醒方式（声音、振动、角标等）。修改 Slot 逻辑影响所有使用该渠道的通知 | `interfaces/inner_api/notification_slot.h` + `services/ans/include/notification_slot_filter.h` |
| LiveView / 实况 | 一种支持实时更新的动态通知类型，有独立的发布流程和订阅管理 | `services/ans/src/advanced_notification_publish/live_publish_process.cpp` + `services/ans/src/system_live_view/` |
| DND / 勿扰 | Do Not Disturb，勿扰模式，控制通知是否静默 | `services/ans/src/disturb_manager/` + `interfaces/inner_api/notification_do_not_disturb_date.h` |
| Parcelable | IPC 序列化接口，所有跨进程传输的数据模型必须实现 | `frameworks/ans/src/notification_*.cpp` |
| NAPI | Node-API，ArkTS 与 C++ 的绑定层 | `interfaces/kits/napi/` + `frameworks/js/` + `frameworks/ets/` |
| IDL | 接口定义语言，用于生成 IPC proxy/stub 代码 | `frameworks/ans/*.idl` |
| 软总线 / SoftBus | 分布式通信基础，不是普通 socket 层 | `services/distributed/include/soft_bus/` |
| SystemAbility | OpenHarmony 系统服务框架，服务端以 SA 形式注册和运行 | `services/ans/include/advanced_notification_service_ability.h` |
| sptr | OpenHarmony 共享指针（`refbase.h`），非 `std::shared_ptr` | 全项目 |
| ErrCode | 错误码返回类型 | `frameworks/core/common/include/ans_inner_errors.h` |
| HWTEST_F | OpenHarmony 测试用例宏 | 全项目测试代码 |
| 特性开关 | `notification.gni` 中的 `declare_args()` 控制条件编译 | `notification.gni` |
| ExtensionAbility | 三方扩展能力框架 | `frameworks/extension/` |

在计划阶段，声明：
- 任务分类
- 已读取的代码路径和文档
- 发现的约束
- 是否需要同步修改其他层（如 API 变更需同步 NAPI/NDK）

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
- 不要修改 `frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/`（非本项目维护）
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

### Done 定义

- 构建通过（子系统 + 单元测试 + 模糊测试）
- 无新增编译警告
- 变更范围与任务要求一致

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果。
