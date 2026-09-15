# 架构检视指南（architecture 维度）— code-check

## 定位

架构维度为**可选维度**（用户在 Step 0 主动选择，或大型/结构性变更时建议选择），检查变更是否
遵守 ANS 分层架构与架构不变量。适用于：新增模块、调整依赖关系、修改公共基础设施、引入 DDD
域层边界的变更。小型补丁式变更选择本维度时，多数检查项为 N/A。

---

## ANS 分层架构（基线）

```
应用层
  ├─ ArkTS 应用 → interfaces/kits/napi (NAPI 绑定)
  │                 ├─ frameworks/js  (动态 ArkTS 绑定)
  │                 └─ frameworks/ets (静态 ArkTS 绑定)
  ├─ C++ 应用/系统组件 → interfaces/inner_api (完整 C++ API, 78 个头文件)
  └─ 原生 C 应用 → interfaces/ndk (精简 C API)
          ↓
客户端 SDK（无业务状态）
  NotificationHelper (frameworks/ans/src, 公共入口, 单例转发)
    → AnsNotification (frameworks/core, IPC 客户端 + 连接管理)
      → IAnsManager proxy (frameworks/ans, IDL 生成)
          ↓ IPC
服务端（业务状态唯一持有者）
  AdvancedNotificationServiceAbility (services/ans, SystemAbility 入口)
    → AdvancedNotificationService (核心业务, 继承 AnsManagerStub)
      ├─ advanced_notification_publish/ (发布)
      ├─ subscriber_manager (订阅)
      ├─ disturb_manager / badge_manager / notification_slot_filter ...
      ├─ DistributedNotificationManager (services/distributed, 软总线)
      └─ services/domain + services/infrastructure (DDD 域层/基础设施层)
```

**依赖方向铁律**：`interfaces ← frameworks/core ← frameworks/ans ← services/*`；
反向依赖（服务端 include 应用层头文件、客户端 include 服务端头文件）为 P0。

---

## 检查清单

### 1. 架构不变量（逐条核对，来自仓库架构约束）

- [ ] **ARCH-01 客户端 SDK 不持有业务状态（ANS 陷阱 A1，全集定义见 [ans-pitfalls.md](ans-pitfalls.md)）**：`frameworks/` 下不得新增业务决策逻辑、业务缓存、可变业务状态；客户端只做参数组装、IPC 转发、连接管理。判定标准：这段逻辑放在服务端是否语义不变？是 → 不该在客户端
- [ ] **ARCH-02 公共 API 表达稳定的能力意图**：`interfaces/inner_api` 不暴露内部实现细节（内部类、线程模型、存储结构）
- [ ] **ARCH-03 权限校验在服务端能力入口**（与安全维度 SEC A5 联动）：客户端校验不得成为唯一防线
- [ ] **ARCH-04 Parcelable 完整性**：跨进程数据模型全部实现 Marshalling/Unmarshalling（与兼容维度 COMP-P 联动）
- [ ] **ARCH-05 公共基础设施影响评估**：`frameworks/core/common/`（日志、错误码、常量、权限定义）被 `frameworks/ans` 与 `frameworks/core` 共同依赖——此处修改必须评估全局影响并检索全部使用方
- [ ] **ARCH-06 分布式场景完备**：离线/重连/版本不匹配/授权变更四场景在设计上均有处理路径（与功能维度 FUNC-15~18 联动）
- [ ] **ARCH-07 DFX 可观测**：关键状态变更有日志/事件（与 DFX 维度 DFX-A06 联动）

### 2. 分层与依赖

- [ ] **ARCH-08 依赖方向**：include 关系符合分层（见上图）；发现反向/跨层直连（如 `frameworks/core` 直接 include `services/` 头文件）为 P0
- [ ] **ARCH-09 服务端内部边界**：`services/ans` ↔ `services/distributed` ↔ `services/domain`/`services/infrastructure` 职责清晰：
  - 域层（domain）不直接依赖具体外部实现，外部依赖经 `services/infrastructure` 适配器（DDD 边界）
  - `services/ans` 不绕过 domain 直接操作 infrastructure 内部（新架构演进方向，新旧共存期按就近原则判断并注明）
- [ ] **ARCH-10 无环依赖**：模块间不形成 include 环
- [ ] **ARCH-11 无重复实现**：同一能力（字符串处理、时间转换、权限判断）不得在多模块各写一份；应下沉 `frameworks/core/common` 或域层公共设施

### 3. 接口设计

- [ ] **ARCH-12 接口职责单一**：新增公共接口单一职责、可组合；"上帝接口"（一个入口带 flag 分支出多行为）为坏味道
- [ ] **ARCH-13 抽象层次一致**：高层模块不感知低层细节（`AdvancedNotificationService` 不感知软总线报文格式，经 `DistributedNotificationManager` 抽象隔离）
- [ ] **ARCH-14 回调设计**：新增回调接口生命周期明确（注册/注销/死亡通知），避免无法释放的回调持有

### 4. 可测试性与演进

- [ ] **ARCH-15 依赖可注入**：外部依赖（DB、分布式、其他 SA）经接口/适配器隔离，可被 mock（`test/mock` 可覆盖）；直接硬编码单例调用链降低可测性
- [ ] **ARCH-16 特性开关边界清晰**：`notification.gni` 开关包裹的代码边界与模块边界一致（开关不横切多个模块的内部实现）
- [ ] **ARCH-17 双套绑定演进一致**：frameworks/js 与 frameworks/ets 的架构决策同步（静态绑定是新演进方向，新能力优先评估 ets 侧）

---

## 检测方法

```bash
# 反向依赖检测（客户端不得 include 服务端头文件）
grep -rn '#include ".*advanced_notification_service\|#include ".*notification_preferences' \
    frameworks/ interfaces/ --include="*.cpp" --include="*.h" | grep -v reminder

# 服务端 include 应用层/客户端头文件（跨层直连）
grep -rn '#include "ans_notification\|#include "notification_helper' \
    services/ --include="*.cpp" --include="*.h"

# frameworks/core/common 修改影响面（该目录变更时必做）
git diff HEAD --name-only | grep "frameworks/core/common/" && \
    echo "公共基础设施变更：检索全部使用方评估影响"

# 无环依赖（模块级人工梳理变更文件的 include 图）
```

## 严重等级映射

| 类别 | 默认等级 |
|---|---|
| 反向/跨层依赖、客户端新增业务状态（A1）、绕过权限入口 | **P0** |
| 破坏 DDD 域边界、重复实现、上帝接口、公共基础设施未评估影响 | **P1** |
| 抽象层次不一致、可测性差、回调生命周期不明 | **P2** |
| 结构优化建议 | **P3** |

## 输出格式

发现以 `ARCH-xxx` 编号输出（见 report-template.md），每条包含：位置、问题、违反的不变量/分层规则、影响（波及哪些模块）、重构建议。小型变更选择本维度时，输出 N/A 说明即可（不视为维度缺失）。原始产出保存至 `.codecheck/raw/architecture.md`。
