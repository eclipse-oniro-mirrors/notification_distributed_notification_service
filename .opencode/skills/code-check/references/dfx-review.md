# DFX 检视指南（dfx 维度）— code-check

## 规范来源

| 官方规范 | 本地路径（OpenHarmony 全仓工作区） | 线上地址 |
|---|---|---|
| OpenHarmony 日志打印规范（Log guide） | `docs/zh-cn/contribute/OpenHarmony-Log-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-Log-guide.md |

> 本文件将官方日志规范**全量内化**（24 条规则），并叠加 ANS 特化 DFX 规则（客户端禁打点、EventReport、
> 事件配置、HiTrace、敏感数据脱敏）。

---

## 第一部分：官方日志打印规范（全量）

### 1. 日志级别（5 级，正确选用）

| 级别 | 适用场景 |
|---|---|
| FATAL | 重大致命异常，程序/功能即将崩溃且无法恢复 |
| ERROR | 错误影响功能正常运行或用户正常使用，可恢复但代价高（重置数据等） |
| WARN | 较严重非预期情况，对用户影响不大，可自动恢复或简单操作恢复 |
| INFO | 业务关键流程节点（可还原主要运行过程）；可预期的非正常情况（无信号、登录失败等）——应由业务内处于支配地位的模块记录，避免在多个被调模块或低级函数重复记录 |
| DEBUG | 更详细的流程记录，正式发布版本默认不打印 |

- [ ] **DFX-L01【规则】根据实际情况正确使用日志级别**（级别与内容实际严重度匹配）

### 2. 日志内容（9 条）

- [ ] **DFX-L02【规则】日志内容用英文描述，拼写无误、符合语法，准确表述含义**（禁止无意义数字、禁止"Error happened"式无上下文日志）
- [ ] **DFX-L03【规则】日志中禁止打印隐私信息**（硬件序列号、个人账号、密码、身份等）
- [ ] **DFX-L04【规则】日志中禁止打印与业务无关的信息**（issue 单号、公司部门、开发者姓名/工号/缩写等）
- [ ] **DFX-L05【规则】日志中禁止打印重复信息**（不同位置内容完全一样的日志，定位时无法区分代码位置）
- [ ] **DFX-L06【规则】禁止在日志打印语句中调用业务接口函数**（日志不得影响业务流程）
- [ ] **DFX-L07【规则】禁止将开发调试日志提交到代码仓**（逐步打印变量、可能含隐私的临时日志必须删除）
- [ ] **DFX-L08【规则】日志中禁止打印文件名、行号信息**（暴露内部实现）
- [ ] **DFX-L09【规则】日志中禁止重复打印 TAG 信息**（使用 HiLog 接口的 tag 参数）
- [ ] **DFX-L10【建议】单条日志长度尽量一行内**（约 100 字符，不超过 160）

### 3. 打印时机（4 条）

- [ ] **DFX-L11【规则】高频代码的正常流程中禁止打印日志**（高频接口、大数据循环、协议流处理等正常分支禁打，错误分支可打）
- [ ] **DFX-L12【规则】可能重复发生的日志需要频率限制**（防止相同信息刷屏冲掉他人日志）
- [ ] **DFX-L13【规则】基本不可能发生的点必须打印日志**（一旦发生即疑难杂症）
- [ ] **DFX-L14【建议】日志字符串在打印时再生成**（延迟构造，日志关闭时零开销）

### 4. 日志形式（5 条固定句式）

- [ ] **DFX-L15【规则】事件记录：`who do what` 主谓宾**（如 `NotificationSubscriberManager add subscriber successful`）
- [ ] **DFX-L16【规则】状态变化：`state_name:s1->s2, reason:msg`**（如 `disturb_mode:NONE->DND, reason:user enable`）
- [ ] **DFX-L17【规则】参数值：`name1=value1, name2=value2`**（如 `bundleName=com.example, userId=100`）
- [ ] **DFX-L18【规则】成功日志：`xxx successful`**
- [ ] **DFX-L19【规则】失败日志：`xxx failed, please xxx`** 且包含可能的解决方案（如 `Connect to distributed service failed, please check network configuration`）

### 5. 常见模式日志（9 类，按需覆盖）

| 模式 | 记录要求 |
|---|---|
| 流程类 | 业务开始点、关键条件分支、错误处理点、结束点 |
| 数据库类 | 增删改查操作 + 发起者 + 结果；**不记录操作内容与结果内容**（防隐私）；查询结果数量可记录；性能敏感场景记录耗时 |
| 文件类 | 创建/打开/读写/关闭/删除/属性操作 + 结果；**文件内容不可记录**；系统文件名可打印，用户文件名不可；批量操作只打一条（记数量） |
| 关键对象/对象池 | 创建、加载、卸载、释放 + 操作主体与结果；状态变化记录前后值 |
| 线程 | 创建/启动/暂停/终止 + 线程号/线程名（重要线程必须命名）；死锁/死循环检测必须打日志；高频消息只打处理失败 |
| 并发控制 | 锁/信号量的创建、占用、释放、等待 + 对象名称与位置 |
| 共享内存 | 创建、删除、设置、查询、销毁 + 操作者与结果 |
| 接口交互 | 调用者、消息内容（脱敏）、处理结果、返回值（脱敏）——IPC/RPC 边界 |
| 状态机 | 状态转换前后状态名 + 外部激励条件 |

- [ ] **DFX-L20【建议】上述 9 类模式按业务实际覆盖**（ANS 映射：流程类=发布/订阅流程；数据库类=偏好设置 RDB；接口交互=AnsManagerStub IPC 边界；状态机=勿扰/订阅生命周期）

### 6. HiLog 接口使用规范（4 条）

- [ ] **DFX-L21【规则】每个业务须有独立的 Domain ID**（向 DFX 申请，不得盗用其他领域；测试代码使用 0xD000F00；系统范围 0xD000000~0xD0FFFFF）
- [ ] **DFX-L22【建议】业务内部按层次/模块粒度细分 Domain ID**（0xD0xxxyy，yy 为领域内自分配）
- [ ] **DFX-L23【规则】日志流量管控阈值（默认 10240 字节/秒/Domain）的修改需 DFX 评审**——高流量打日志会被丢弃
- [ ] **DFX-L24【规则】正确填写格式化隐私参数标识 `{public}`/`{private}`**：`{public}` 明文输出，`{private}` 输出 `<private>` 过滤回显；禁止不分析内容随意设置

---

## 第二部分：ANS DFX 特化

### 2.1 日志基础设施（仓内事实）

| 组件 | 位置 | 说明 |
|---|---|---|
| 日志宏 | `frameworks/core/common/include/ans_log_wrapper.h` | `ANS_LOGF/E/W/I/D`，Domain `0xD001203`，Tag `"Ans"` |
| 流控支持 | 同上 | `ANS_LOG_LIMIT_INTERVALS`（10s 间隔限流宏）——满足 DFX-L12 |
| Trace 宏 | `frameworks/core/common/include/ans_trace_wrapper.h` | `NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION)` |
| 打点入口 | `services/ans/include/event_report.h` | `EventReport::SendHiSysEvent(eventName, eventInfo)` + `InnerSend*`（PublishError/Subscribe/EnableNotification/DialogClick/FlowControlOccur 等） |
| 事件配置 | 仓根 `hisysevent.yaml`、`hisysevent_notification_ue.yaml` | 事件 domain/name/params 定义——新增事件必须同步登记 |
| 特性开关 | `notification.gni` | `hisysevent_usage`（打点）、`ans_hitrace_usage`（Trace）——直接调用需条件编译包裹 |

### 2.2 架构红线：客户端禁止打点

**`frameworks/`（客户端 SDK：frameworks/ans、core、js、ets、extension）禁止 HiSysEvent 打点。**
（本仓现状已验证：frameworks/ 下零 `HiSysEventWrite` 调用）

理由：事件统一在服务端管理（去重/权限/参数一致性/防伪造），客户端打点造成重复事件与性能浪费。

| 代码位置 | HiSysEvent 打点 | HiLog 日志 |
|---|---|---|
| `services/ans/`、`services/distributed/`、`services/domain/` | ✅ 允许（经 EventReport） | ✅ 允许 |
| `frameworks/`（全部子目录） | ❌ **禁止** | ✅ 允许（ANS_LOG*） |
| `interfaces/`（inner_api/kits/ndk） | ❌ **禁止** | ✅ 允许 |

- [ ] **DFX-A01**：`frameworks/`、`interfaces/` 下不得出现 `HiSysEventWrite` / `EventReport::SendHiSysEvent` 调用（P0 架构红线）
- [ ] **DFX-A02**：服务端新业务操作（发布失败/订阅异常/开关失败/流控）应通过 `EventReport` 上报，故障路径优先（`InnerSendPublishErrorEvent` 等模式）
- [ ] **DFX-A03**：新增事件必须先在 `hisysevent.yaml` 登记（domain/name/params），未登记事件会被丢弃
- [ ] **DFX-A04**：直接调用 HiSysEventWrite（不经 EventReport）必须包裹 `#ifdef HAS_HISYSEVENT_PART` 等特性开关条件编译

### 2.3 事件场景区分（对齐官方"场景区分"要求）

同一操作在不同触发场景应可区分，`EventInfo` 填充完整（bundleName、userId、errCode、调用方信息）：

| 业务 | 行为事件 | 故障事件 |
|---|---|---|
| 通知发布 | 发布成功（含场景：普通/实况窗 LiveView） | `InnerSendPublishErrorEvent` |
| 订阅 | 订阅/退订 | `InnerSendSubscribeErrorEvent` |
| 通知开关 | Enable/Disable 通知、Slot | `InnerSendEnableNotificationErrorEvent` / `InnerSendEnableNotificationSlotErrorEvent` |
| 流控 | — | `InnerSendFlowControlOccurEvent`（通知数量达到上限） |
| 弹窗 | 授权弹窗点击 | — |

- [ ] **DFX-A05**：新事件能区分触发场景（调用来源/成功失败），EventInfo 字段完整
- [ ] **DFX-A06**：关键状态变更可观测（架构不变量）：通知增删、订阅增减、勿扰开关、分布式连接状态——无任何日志/事件的静默状态变更是缺陷

### 2.4 隐私脱敏（ANS 高敏场景）

**通知标题/内容/子文本是用户敏感数据**：

- [ ] **DFX-A07**：日志中通知内容相关字段一律 `%{private}s`（ANS_LOG 宏内 `{private}`）；bundleName、userId、errCode 等业务标识可 `%{public}`
- [ ] **DFX-A08**：HiSysEvent 事件参数禁止携带通知明文内容（只带 bundleName/数量/错误码等元数据）
- [ ] **DFX-A09**：设备名、设备 ID（分布式场景）按敏感数据处理

### 2.5 HiTrace

- [ ] **DFX-A10**：预期耗时 >10ms 的操作（偏好设置 RDB 读写、分布式同步、LiveView 处理）使用 `NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION)` 包裹（RAII 作用域，禁用 Start/Finish 手工对）
- [ ] **DFX-A11**：高频路径避免复杂 trace（CountTrace 计数替代详细 trace）

---

## 检测命令

```bash
EXCLUDE="--exclude-dir=reminder --exclude-dir=cj --exclude-dir=reminder_ani"

# 客户端违规打点（P0 架构红线；排除非维护目录）
grep -rn "HiSysEventWrite\|SendHiSysEvent\|EventReport::" frameworks/ interfaces/ --include="*.cpp" --include="*.h" $EXCLUDE

# 敏感数据 public 打印（人工复核）
grep -rn "%{public}s" --include="*.cpp" services/ $EXCLUDE | grep -iE "title|content|text|message|device"

# 调试日志残留（提交前必须清除）
git diff HEAD | grep -E "^\+.*ANS_LOGD\(" | grep -vE "ANS_LOGD.*failed|ANS_LOGD.*error"

# 错误路径无日志（抽样人工复核）
grep -rn "return ERR_" --include="*.cpp" services/ans/src/ $EXCLUDE | head -20

# 新增事件是否登记
git diff HEAD --name-only | grep -E "\.cpp$" | xargs grep -l "SendHiSysEvent" 2>/dev/null # 对比 hisysevent.yaml 是否含该事件名

# 文件名/行号打印（官方禁令）
grep -rn "__LINE__\|__FILE__" --include="*.cpp" --include="*.h" services/ $EXCLUDE | grep -i "log"
```

## 严重等级映射

| 类别 | 默认等级 |
|---|---|
| 客户端打点（DFX-A01）、删除 DFX 诊断信息 | **P0** |
| 隐私数据 %{public}、事件未登记、错误路径完全静默 | **P1** |
| 日志级别/形式/时机违规、高频路径打 INFO | **P2** |
| 建议性覆盖补全 | **P3** |

## 输出格式

发现以 `DFX-xxx` 编号输出（见 report-template.md），每条包含：位置、问题、规范依据（DFX-LXX 官方规则 / DFX-AXX ANS 特化）、修复建议。原始产出保存至 `.codecheck/raw/dfx.md`。
