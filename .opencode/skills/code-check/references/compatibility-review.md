# 兼容性检视指南（compatibility 维度）— code-check

## 定位

兼容性维度保障变更**不破坏既有调用方与既有数据**。覆盖：公共 API、IPC 序列化（Parcelable）、
IDL 接口、ArkTS 双套绑定、NDK 符号、RDB schema、分布式协议跨设备版本。
本维度集中了 ANS 兼容类特有陷阱 A2/A3/A4/A6/A9 及 A7 的协议部分（陷阱编号全集定义见
[ans-pitfalls.md](ans-pitfalls.md)）。

> 参考规范：OpenHarmony API 治理章程（https://gitcode.com/openharmony/docs/blob/master/zh-cn/design/OpenHarmony-API-governance.md）；
> ANS 仓库 AGENTS.md 架构约束。

---

## 检查清单

### 1. 公共 API 红线（ANS 陷阱 A9）— 原则上全部 P0

修改以下任一内容即破坏性变更，任务未明确要求时**直接拦截**：

- [ ] **COMP-A01** 公共 API 签名变更：参数类型/数量/顺序、返回类型（`interfaces/inner_api/` 全部 78 个头文件）
- [ ] **COMP-A02** 错误码语义变更：现有错误码含义改变；相同输入从错误码 A 变为 B
- [ ] **COMP-A03** 权限行为变更：对外接口新增权限校验；权限开放范围收紧
- [ ] **COMP-A04** 生命周期/回调语义变更：回调触发时机/时序改变；删除生命周期回调
- [ ] **COMP-A05** 返回数据修改：接口返回的数据结构内容变化（字段删除/语义变化）
- [ ] **COMP-A06** 参数规格收紧：取值范围缩小、系统可创建实例数量收紧
- [ ] **COMP-A07** 新增错误抛出：对已有场景新增错误码（老调用方未处理新错误码会行为异常）
- [ ] **COMP-A08** 接口性能明显劣化（对高频查询接口）

**API 变更联动检查**（改一层必查三层）：

- [ ] **COMP-A09** `interfaces/inner_api/` C++ API 变更 → 同步检查 `interfaces/kits/napi/`（ArkTS NAPI 绑定）与 `interfaces/ndk/`（NDK C 接口）是否需要同步
- [ ] **COMP-A10** NAPI 接口声明（d.ts/@ohos.notification.d.ts 等）与实现同步；新增接口需版本标注
- [ ] **COMP-A11** 接口使用约束/规格文档同步更新

### 2. Parcelable 序列化兼容（ANS 陷阱 A2）

所有跨进程数据模型（`frameworks/ans/src/notification_*.cpp`）的 `Marshalling`/`Unmarshalling`：

- [ ] **COMP-P01** 新增字段必须**追加在读写序列的末尾**，禁止插入中间
- [ ] **COMP-P02** 读顺序与写顺序严格一致
- [ ] **COMP-P03** 新字段必须处理旧版本数据（默认值/缺省分支），Unmarshalling 对缺失字段不得失败
- [ ] **COMP-P04** 字段增删需全量检查所有读写点（拷贝构造、赋值、Dump 是否同步）
- [ ] **COMP-P05** 序列化数组前校验大小上限（超大数组拒绝，防内存攻击——与安全维度 SEC 重叠时合并）

### 3. IDL 接口（ANS 陷阱 A3）

`frameworks/ans/*.idl`（IAnsManager、IAnsSubscriber、IAnsDialogCallback、IAnsOperationCallback、IAnsResultDataSynchronizer、IAnsSubscriberLocalLiveView、IBadgeQueryCallback、ISwingCallBack）：

- [ ] **COMP-I01** 新增接口**只能追加在 IDL 文件末尾**（IPC code 按位置分配，中间插入会移动后续接口 code，破坏二进制兼容）

  ```idl
  // ❌ 错误：中间插入，后续接口 code 全部位移
  interface OHOS.Notification.IAnsManager {
      void Publish(...);          // code = 1
      void NewMethod(...);        // ❌ 插在这
      void Cancel(...);           // code 2 → 3，老 proxy 调错接口
  }
  // ✅ 正确：末尾追加
  ```

- [ ] **COMP-I02** 禁止删除/交换现有接口顺序
- [ ] **COMP-I03** 禁止直接修改 IDL 生成的 proxy/stub 代码（`*.cpp`/`*.h` 生成物），必须改 `.idl` 源文件重新生成
- [ ] **COMP-I04** IDL 变更后 proxy（frameworks/ans）与 stub 实现（services/ans）两侧同步

### 4. ArkTS 双套绑定同步（ANS 陷阱 A4）

`frameworks/js/`（动态绑定）与 `frameworks/ets/`（静态绑定）**功能一致**：

- [ ] **COMP-J01** 修改任一套的接口行为/参数处理/错误码映射，必须检查另一套是否需要同步修改
- [ ] **COMP-J02** 两套绑定的接口列表、参数校验行为保持一致（差异需有明确技术理由）

### 5. NDK 版本脚本冻结（ANS 陷阱 A6）

- [ ] **COMP-M01** 禁止修改 `*.map` 中已有符号的可见性：`interfaces/ndk/libohnotification.map`、`frameworks/js/napi/*.map`、`frameworks/ets/ani/*.map`（P0 红线，与 checklist CHK-G06 重叠时合并）
- [ ] **COMP-M02** 新增导出符号追加在 map 对应版本节点；新版本节点遵循版本脚本管理流程

### 6. 持久化数据兼容

- [ ] **COMP-D01** RDB schema（偏好设置，`services/infrastructure/external_adapter/rdb` + `services/domain/settings/rdb_mgr_repo`）变更必须提供旧版本数据升级路径，并在测试中覆盖升级场景
- [ ] **COMP-D02** 分布式偏好（`services/distributed/src/distributed_preferences*.cpp`）数据格式变更考虑对端旧版本可解析（或版本协商降级）

### 7. 分布式协议跨设备版本（ANS 陷阱 A7 协议部分）

- [ ] **COMP-Z01** 跨设备同步报文（TLV 等，`services/distributed/src/soft_bus/` 实现、`services/distributed/include/soft_bus/` 头文件）字段变更必须考虑**版本不匹配**的对端设备：新增字段可被旧版本忽略或安全跳过；不得假设对端同版本
- [ ] **COMP-Z02** 协议变更不改变现有报文的解析语义（新能力用新报文类型/新字段承载）
- [ ] **COMP-Z03** 授权变更场景：设备解除授权后的数据处理路径不受协议变更影响

### 8. 枚举与常量稳定性

- [ ] **COMP-E01** 公共枚举（通知类型、Slot 类型、勿扰模式等 `interfaces/inner_api/` 枚举）不得改变既有值
- [ ] **COMP-E02** 常量语义（数量上限、超时时间）变更评估对现有调用方的影响，收紧需确认

---

## 检测方法

```bash
# IDL 变更检测（中间插入检测：对比新旧接口顺序）
git diff HEAD -- frameworks/ans/*.idl
# 检查点：新增行是否都在文件末尾的 } 之前，且无删除行

# Parcelable 读写对称性（人工复核新增字段位置）
git diff HEAD -- frameworks/ans/src/notification_*.cpp | grep -A5 -B5 "WriteInt32\|WriteString\|ReadInt32\|ReadString"

# .map 变更（P0 红线）
git diff HEAD --name-only | grep "\.map$"

# 三层联动检查
git diff HEAD --name-only | grep "interfaces/inner_api/" && echo "必须检查 napi/ndk 是否需同步"

# js/ets 双套同步
git diff HEAD --name-only | grep -E "frameworks/(js|ets)/" && echo "必须检查另一套绑定"
```

## 严重等级映射

| 类别 | 默认等级 |
|---|---|
| API 签名/错误码/权限/生命周期破坏（COMP-A01~A08）、IDL 中间插入、map 符号可见性修改 | **P0** |
| Parcelable 字段中间插入、旧版本默认值缺失、RDB 无升级路径、分布式协议不兼容旧对端、js/ets 未同步 | **P1** |
| 枚举值依赖脆弱、三层联动文档缺失 | **P2** |
| 建议性改进 | **P3** |

## 输出格式

发现以 `COMP-xxx` 编号输出（见 report-template.md），每条包含：位置、问题、影响（破坏哪个版本的哪个调用方）、规范依据（COMP-XX / 陷阱编号）、修复建议。原始产出保存至 `.codecheck/raw/compatibility.md`。
