# ANS 特有陷阱汇总（A1~A9）— code-check

> 本文件是 code-check 技能中 **ANS 陷阱编号 A1~A9 的唯一权威定义**。
> 各维度检视指南引用的陷阱编号均以本文件为准；对应检查项的详细规则在所属维度指南中展开。
> 来源：本仓架构约束（AGENTS.md）与通知子系统历史问题沉淀。

| 编号 | 陷阱名称 | 一句话描述 | 主责维度（检查项） |
|---|---|---|---|
| A1 | 客户端无业务状态 | `frameworks/`（客户端 SDK）不持有业务状态、不做业务决策，所有业务逻辑在服务端 `services/` 执行 | architecture（ARCH-01） |
| A2 | Parcelable 序列化兼容 | 跨进程数据模型新增字段必须追加在 Marshalling/Unmarshalling 读写序列末尾，读写顺序一致，旧版本数据有默认值 | compatibility（COMP-P01~P05） |
| A3 | IDL 接口末尾追加 | IDL 接口按位置分配 IPC code，新接口只能追加在文件末尾；禁止直接修改生成的 proxy/stub 代码 | compatibility（COMP-I01~I04）、checklist（CHK-P07） |
| A4 | js/ets 双套同步 | `frameworks/js/` 与 `frameworks/ets/` 两套 ArkTS 绑定功能一致，改一套必查另一套是否需同步 | compatibility（COMP-J01~J02） |
| A5 | 权限校验在服务端 | 权限校验必须在服务端能力入口（`services/ans`）完成，客户端校验不得成为唯一防线 | security（3.1 节） |
| A6 | .map 符号冻结 | 禁止修改 `*.map` 版本脚本中已有符号的可见性 | compatibility（COMP-M01~M02）、checklist（CHK-G06） |
| A7 | 分布式四场景 | 分布式通知必须处理离线、重连、版本不匹配、授权变更四个场景（行为正确性 + 协议兼容性） | functionality（FUNC-15~18 行为）、compatibility（COMP-Z01~Z03 协议） |
| A8 | 非维护目录禁改 | `frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/` 由其他团队维护，禁止修改 | checklist（CHK-R01） |
| A9 | 公共 API 红线 | 公共 API 签名、错误码、权限行为、生命周期语义、返回数据不可变（任务未明确要求时直接拦截） | compatibility（COMP-A01~A08） |
