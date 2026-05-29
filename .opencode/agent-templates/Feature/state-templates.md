# 状态文件模板

本文件包含 Feature-Agent 使用的状态文件相关模板。

**重要约定**：
- 所有过程文档存放在 `.opencode/kb/features/${feature-name}/` 目录下
- `${feature-name}`：需求名称，用作目录名，英文小写字母，多个单词用 `-` 连接
- 状态文件：`feature-state.json`，由 **Feature-State-SubAgent** 管理

---

## 1. 状态文件结构模板

使用以下结构维护需求实现全局状态：

```json
{
  "feature_name": "<需求名称>",
  "kb_dir": ".opencode/kb/features/<需求名称>",
  "feature_requirement": "<用户提供的原始需求描述>",
  "entry_points": [],
  "excludes": [],
  "acceptance_criteria": [],
  "created_at": "<ISO时间戳>",
  "current_phase": "architecture",
  "approval_history": [],
  "phases": {
    "architecture": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/feature-architecture.md"
      ],
      "user_interactions_done": false
    },
    "dev_design": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/feature-dev-design.md",
        ".opencode/kb/features/${feature-name}/feature-context.md"
      ],
      "approval": {
        "status": "pending",
        "approved_at": null,
        "summary": null
      }
    },
    "plan": {
      "status": "pending",
      "output": ".opencode/kb/features/${feature-name}/feature-plan.md",
      "approval": {
        "status": "pending",
        "approved_at": null,
        "summary": null
      }
    },
    "execute": {
      "status": "blocked",
      "blocked_by": ["dev_design_approval", "plan_approval"],
      "current_task": null,
      "dag": {},
      "tasks": {},
      "file_locks": [],
      "updated_at": null
    },
    "doc": {
      "status": "pending",
      "outputs": [
        ".opencode/kb/features/${feature-name}/${feature-name}.md",
        ".opencode/kb/features/${feature-name}/feature-test-report.md"
      ]
    }
  },
  "test_coverage": {
    "unit_tests": [],
    "functional_tests": [],
    "performance_tests": [],
    "coverage_target": "90%"
  },
  "verify_log": ".opencode/kb/features/${feature-name}/verify-log.md"
}
```

**字段说明**:
- `feature_name`：需求名称，用作目录名，由 Architecture 子代理分析后生成或用户指定
- `kb_dir`：完整知识库路径 `.opencode/kb/features/${feature-name}`
- `feature_requirement`：用户提供的原始需求描述
- `phases.architecture.user_interactions_done`：标记 Architecture 阶段的用户交互是否完成
- `execute.tasks`：任务字典（object格式），key为task_id，value为任务状态对象
- `execute.dag`：任务依赖关系图（object格式），key为task_id，value为依赖列表

---

## 2. Execute 阶段字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `execute.status` | string | execute 阶段整体状态：blocked / pending / running / done |
| `execute.blocked_by` | array | 阻塞原因列表：dev_design_approval / plan_approval |
| `execute.current_task` | string | 当前正在执行的任务 ID |
| `execute.dag` | object | 任务依赖关系图，key为task_id，value为依赖列表 |
| `execute.tasks` | object | 任务字典，key为任务 ID，value为任务状态对象（必须是object格式，不能是array） |
| `execute.file_locks` | array | 文件锁列表，记录被锁定的文件和锁定者 |
| `execute.updated_at` | string | execute 阶段状态最后更新时间（ISO 时间戳） |

---

## 3. Task 状态字段说明

每个任务对象包含以下字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 任务唯一标识（如 T001） |
| `name` | string | 任务名称 |
| `type` | string | 任务类型：core_implementation / extended_features / test_validation / documentation |
| `depends` | array | 依赖的任务 ID 列表 |
| `files_write` | array | 可写文件路径列表 |
| `files_read` | array | 只读文件路径列表 |
| `acceptance_criteria` | array | 验收标准列表 |
| `test_commands` | array | 测试命令列表 |
| `evidence_required` | array | 需要的证据产物列表 |
| `risk_level` | string | 风险等级：low / medium / high |
| `description` | string | 任务描述 |
| `status` | string | 任务状态：pending / running / done / failed / human_review |
| `retry_count` | integer | 当前重试次数（0-3） |
| `last_error` | string | 最后一次失败的错误信息 |
| `verified` | boolean | 是否已通过 Verify 子代理验证 |
| `started_at` | string | 任务开始时间（ISO 时间戳） |
| `completed_at` | string | 任务完成时间（ISO 时间戳） |
| `files_locked` | array | 当前锁定的文件路径列表 |
| `files_changed` | array | 实际修改的文件路径列表 |

---

## 4. File Locks 字段说明

每个文件锁对象包含以下字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `file` | string | 被锁定的文件路径（相对于工作区根目录） |
| `locked_by` | string | 锁定该文件的任务 ID |
| `locked_at` | string | 锁定时间（ISO 时间戳） |

---

## 5. 审批历史记录模板

`approval_history` 采用追加写入，单条记录结构如下：

```json
{
  "phase": "architecture | dev_design | plan",
  "decision": "approved | rejected | revised",
  "approved_by": "user",
  "approved_at": "<ISO时间戳>",
  "summary": "<用户确认摘要>",
  "document": "<对应阶段的产物文档路径>"
}
```

**示例**：

```json
[
  {
    "phase": "architecture",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T10:45:00Z",
    "summary": "架构设计文档已确认，需求名称确定为 notification-group-management",
    "document": ".opencode/kb/features/notification-group-management/feature-architecture.md"
  },
  {
    "phase": "dev_design",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T11:30:00Z",
    "summary": "开发设计方案已确认，可以开始任务分解",
    "document": ".opencode/kb/features/notification-group-management/feature-dev-design.md"
  },
  {
    "phase": "plan",
    "decision": "approved",
    "approved_by": "user",
    "approved_at": "2026-05-06T12:00:00Z",
    "summary": "任务计划已确认，共5个任务，按DAG依赖执行",
    "document": ".opencode/kb/features/notification-group-management/feature-plan.md"
  }
]
```

---

## 6. DAG 依赖关系图示例

DAG 使用 object 格式，key 为 task_id，value 为该任务的依赖列表：

```json
{
  "T001": [],
  "T002": ["T001"],
  "T003": ["T001"],
  "T004": ["T002", "T003"],
  "T005": ["T004"]
}
```

**含义说明**：
- T001 无依赖，可最先执行
- T002 和 T003 依赖 T001，T001 完成后可并发执行
- T004 依赖 T002 和 T003，两者都完成后才能执行
- T005 依赖 T004，T004 完成后才能执行

---

## 7. 运行时状态示例

以下是 Execute 阶段运行时的状态文件示例：

```json
{
  "execute": {
    "status": "running",
    "blocked_by": [],
    "current_task": "T002",
    "dag": {
      "T001": [],
      "T002": ["T001"],
      "T003": ["T001"],
      "T004": ["T002", "T003"],
      "T005": ["T004"]
    },
    "tasks": {
      "T001": {
        "id": "T001",
        "name": "实现 NotificationGroup 类",
        "type": "core_implementation",
        "status": "done",
        "retry_count": 0,
        "last_error": null,
        "verified": true,
        "started_at": "2026-05-06T10:38:00Z",
        "completed_at": "2026-05-06T10:45:00Z",
        "files_locked": [],
        "files_changed": [
          "frameworks/ans/core/notification_group.h",
          "frameworks/ans/core/notification_group.cpp"
        ],
        "depends": [],
        "files_write": ["frameworks/ans/core/notification_group.h", "frameworks/ans/core/notification_group.cpp"],
        "files_read": ["frameworks/ans/core/notification_manager.h"],
        "acceptance_criteria": ["类定义完整", "基本方法实现"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["源代码文件"],
        "risk_level": "low",
        "description": "实现 NotificationGroup 类"
      },
      "T002": {
        "id": "T002",
        "name": "实现分组创建接口",
        "type": "core_implementation",
        "status": "running",
        "retry_count": 0,
        "last_error": null,
        "verified": false,
        "started_at": "2026-05-06T10:45:00Z",
        "completed_at": null,
        "files_locked": ["frameworks/ans/core/notification_manager.cpp"],
        "files_changed": [],
        "depends": ["T001"],
        "files_write": ["frameworks/ans/core/notification_manager.cpp"],
        "files_read": ["frameworks/ans/core/notification_group.h"],
        "acceptance_criteria": ["接口定义完整", "实现逻辑正确"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["接口定义文档", "实现代码"],
        "risk_level": "medium",
        "description": "在 NotificationManager 中实现分组创建接口"
      },
      "T003": {
        "id": "T003",
        "name": "实现分组查询接口",
        "type": "core_implementation",
        "status": "pending",
        "retry_count": 0,
        "last_error": null,
        "verified": false,
        "started_at": null,
        "completed_at": null,
        "files_locked": [],
        "files_changed": [],
        "depends": ["T001"],
        "files_write": ["frameworks/ans/core/notification_manager.cpp"],
        "files_read": ["frameworks/ans/core/notification_group.h"],
        "acceptance_criteria": ["接口定义完整", "实现逻辑正确"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["接口定义文档", "实现代码"],
        "risk_level": "medium",
        "description": "在 NotificationManager 中实现分组查询接口"
      },
      "T004": {
        "id": "T004",
        "name": "编写单元测试",
        "type": "test_validation",
        "status": "pending",
        "retry_count": 0,
        "last_error": null,
        "verified": false,
        "started_at": null,
        "completed_at": null,
        "files_locked": [],
        "files_changed": [],
        "depends": ["T002", "T003"],
        "files_write": ["test/unittest/notification_group_test.cpp"],
        "files_read": [
          "frameworks/ans/core/notification_group.h",
          "frameworks/ans/core/notification_manager.cpp"
        ],
        "acceptance_criteria": ["测试覆盖核心功能", "测试编译通过"],
        "test_commands": ["./build.sh --product-name rk3568 --build-target distributed_notification_service_test"],
        "evidence_required": ["测试代码文件"],
        "risk_level": "low",
        "description": "编写 NotificationGroup 的单元测试"
      },
      "T005": {
        "id": "T005",
        "name": "更新文档",
        "type": "documentation",
        "status": "pending",
        "retry_count": 0,
        "last_error": null,
        "verified": false,
        "started_at": null,
        "completed_at": null,
        "files_locked": [],
        "files_changed": [],
        "depends": ["T004"],
        "files_write": ["docs/notification_group_usage.md"],
        "files_read": [],
        "acceptance_criteria": ["文档完整", "示例代码可运行"],
        "test_commands": [],
        "evidence_required": ["文档文件"],
        "risk_level": "low",
        "description": "更新 NotificationGroup 使用文档"
      }
    },
    "file_locks": [
      {
        "file": "frameworks/ans/core/notification_manager.cpp",
        "locked_by": "T002",
        "locked_at": "2026-05-06T10:45:00Z"
      }
    ],
    "updated_at": "2026-05-06T10:46:00Z"
  }
}
```