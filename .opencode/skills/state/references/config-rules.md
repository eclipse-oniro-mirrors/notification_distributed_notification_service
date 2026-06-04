# 配置规则说明

本文件说明各 Agent/Skill 的配置规则和选择依据。

## 目录变量约定

所有过程文档使用统一的目录变量：

| 变量 | 说明 | 示例 |
|------|------|------|
| `{kb_dir}` | 工作目录，由调用方指定 | `<caller-specified-path>/` |
| `{name}` | 需求/问题名称，用作目录名，英文小写字母，多个单词用 `-` 连接 | notification-group-management |

**重要约定**：
- 所有目录名都不包含时间戳，保持简洁便于引用
- `{kb_dir}` 由调用方决定，Skill 不硬编码路径

**路径示例**：
- 文档目录：`<caller-specified-path>/`
- 架构文档：`{kb_dir}/architecture.md`

---

## Temperature 配置规则

Temperature 控制 Agent 的创造性程度：

| 值 | 输出特点 | 适用场景 | 示例 |
|----|----------|----------|------|
| 0 | 严格遵守模板，输出确定性高，不偏离设计 | 严格执行、验证、总结 | 架构设计必须覆盖6维度，不能遗漏；验证必须严格执行标准 |
| 0.1 | 高度确定性，极少创造，减少误判 | 编译诊断、错误分析 | 编译验证需要精确诊断，不能臆测错误原因 |
| 0.2 | 允许适度创造，但保持结构化，输出多样性提高 | 设计、规划、执行 | 开发设计可以灵活选择实现方案；任务执行可以创新解决技术问题 |

**配置依据**：

| Agent | Temperature | 原因 | 实际效果 |
|-------|-------------|------|----------|
| 主代理 | 0 | 编排流程，需要严格按流程执行 | 状态管理确定性高，流程不偏离设计 |
| Architecture | 0.2 | 架构设计需要适度创造，与架构师深度交互 | 可以灵活分析需求，但必须严格覆盖6维度 |
| Dev-Design | 0.2 | 开发设计需要适度创造，生成代码示例 | 可以灵活选择实现方案，但必须包含完整的代码框架 |
| Plan | 0.2 | 任务分解需要适度创造，设计执行顺序 | 可以灵活划分任务粒度，但必须保持结构化输出 |
| Execute | 0.2 | 任务执行需要适度创造，解决技术问题 | 可以创新解决实现难点，但必须满足验收标准 |
| Review | 0.2 | 代码检视需要适度灵活，识别多种质量问题 | 可以灵活发现代码问题，但必须严格执行规范 |
| Build | 0.1 | 编译验证需要高度确定性，减少误判 | 编译诊断结果确定性高，不会误判错误类型 |
| Doc | 0.2 | 总结文档需要适度创造，组织信息 | 可以灵活组织文档结构，但必须包含完整内容 |

---

## Permission 配置规则

Permission 控制 Agent 的文件操作权限：

| 权限类型 | 值 | 适用场景 |
|----------|-----|----------|
| write | allow | 设计阶段生成文档，不需要用户确认 |
| write | ask | 执行阶段修改代码，需要用户确认每个修改 |
| edit | allow | 设计阶段修改文档，不需要用户确认 |
| edit | ask | 执行阶段修改代码，需要用户确认每个修改 |

**配置依据**：

| Agent | write | edit | 原因 |
|-------|-------|------|------|
| 主代理 | allow | allow | 编排流程，生成状态文件和调用子代理，不修改业务代码 |
| Architecture | allow | allow | 架构设计阶段生成文档，需要灵活生成和修改架构文档 |
| Dev-Design | allow | allow | 开发设计阶段生成文档，需要灵活生成和修改设计文档 |
| Plan | allow | allow | 任务计划阶段生成文档，需要灵活生成和修改计划文档 |
| Execute | allow | allow | 任务执行修改代码，需要灵活生成和修改源文件 |
| Review | allow | allow | 检视阶段需要写入检视日志，不需要用户确认 |
| Build | allow | allow | 编译验证阶段需要写入编译日志，不需要用户确认 |
| Doc | ask | ask | 总结文档需要用户确认内容是否符合预期 |

---

## Tools 配置规则

各 Agent 的工具权限配置：

| Agent | bash | task | 原因 |
|-------|------|------|------|
| 主代理 | true | true | 需要bash创建目录/重命名，需要task调用子代理 |
| Architecture | true | true | 可能需要bash重命名目录，需要task调用explore |
| Dev-Design | true | true | 设计阶段可能需要bash辅助探索，需要task调用explore |
| Plan | true | true | 规划阶段可能需要bash辅助探索，需要task调用explore |
| Execute | true | true | 执行阶段需要bash运行测试命令，需要task调用explore |
| Review | true | true | 检视阶段需要bash辅助检查，需要task调用explore |
| Build | true | true | 编译验证需要bash执行编译命令和诊断脚本，需要task加载skill |
| Doc | true | true | 总结阶段需要bash辅助收集信息，需要task调用explore |

**bash权限限制**：

主代理的 bash 权限仅限于以下编排型动作：
- 生成时间戳（YYYYMMDD-HHMMSS）
- 创建工作目录结构
- 重命名目录（从临时名改为正式名）
- 状态文件存在性检查
- 必要的文件系统操作（mkdir、mv、ls）

---

## Mode 配置规则

Agent 的运行模式：

| 值 | 适用场景 |
|----|----------|
| primary | 主代理，负责编排和决策 |
| subagent | 子代理，负责执行具体任务 |

**配置依据**：
- 主代理：primary
- 所有子代理/Skill：subagent

---

## 状态字段类型规则

状态文件中的字段类型约定：

| 字段 | 类型 | 说明 |
|------|------|------|
| `execute.tasks` | object | 任务字典，key为task_id，value为任务状态对象（**不能是array**） |
| `execute.dag` | object | 任务依赖关系图，key为task_id，value为依赖列表 |

---

## 审批历史规则

approval_history 的追加规则：

| 阶段 | 是否追加 | 原因 |
|------|----------|------|
| Architecture | 是 | 架构师确认是关键决策点，需要记录 |
| Dev-Design | 是 | 开发人员确认是关键决策点，需要记录 |
| Plan | 是 | 用户确认任务计划是关键决策点，需要记录 |
| Execute | 否 | 任务执行不需要审批，由验证结果决定 |
| Doc | 否 | 总结阶段不需要审批 |

**追加时机**：
- 仅在用户明确批准后才追加
- 每次审批追加一条记录，不能覆盖旧记录
- 用于续跑和审计

---

## 调用子代理规则

调用方调用子代理时的参数传递规则：

### 必传参数

所有子代理必须接收：
- `kb_dir`：文档存放目录

### 阶段特定参数

| 子代理 | 额外参数 | 说明 |
|--------|----------|------|
| Architecture | name, requirement | 需求名称和原始需求描述 |
| Dev-Design | name, requirement, architecture.md | 需求名称、原始需求和架构文档 |
| Plan | architecture.md, dev-design.md | 架构和设计文档 |
| Execute | task_id, retry_count | 任务ID和重试次数 |
| Review | task_id, files_changed, planned_files_write, planned_files_read, acceptance_criteria | 任务变更和验收标准 |
| Build | task_ids, files_changed, test_commands | 任务ID列表、变更文件和编译命令 |
| Doc | name, state.json | 需求名称、全局状态和审批历史 |

---

## 目录重命名规则

Architecture 阶段完成后，目录重命名流程：

| 步骤 | 执行者 | 操作 |
|------|--------|------|
| 1. 生成需求名称 | Architecture | 分析架构文档，生成需求名称建议 |
| 2. 确认需求名称 | 用户 | 与架构师确认最终需求名称 |
| 3. 执行重命名 | 主代理 | 使用bash命令重命名目录 |
| 4. 更新状态文件 | 主代理 | 更新name、kb_dir字段 |

**重命名时机**：
- 必须在用户批准 Architecture 后立即执行
- 重命名后再进入 Dev-Design 阶段

