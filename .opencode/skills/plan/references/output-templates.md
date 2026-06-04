# Plan 阶段输出文件模板

本文件包含 Plan Skill 产出的文件模板。

**重要约定**：
- 所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定
- `{name}`：需求/问题名称，用作目录名，英文小写字母，多个单词用 `-` 连接
- 模板中的路径需要替换为实际路径

---

## 1. plan.md 输出文件模板（Markdown格式）

文件路径：`{kb_dir}/plan.md`

实际路径示例：`{kb_dir}/plan.md`

```markdown
# Plan - 任务分解计划

## 1. 任务列表

| ID | 名称 | 类型 | 依赖 |
|----|------|------|------|
| T001 | 实现 NotificationGroup 类 | 核心实现 | - |
| T002 | 实现分组创建接口 | 核心实现 | T001 |
| T003 | 实现分组查询接口 | 核心实现 | T001 |

## 2. DAG 任务图

<使用 mermaid 表示任务依赖关系图>

## 3. 按类型分组

### 核心实现
- T001: 实现 NotificationGroup 类
- T002: 实现分组创建接口
- T003: 实现分组查询接口

### 扩展功能
- T004: 实现分组排序功能
- T005: 实现分组重命名功能

### 测试验证
- T006: 编写单元测试
- T007: 编写功能测试
- T008: 执行测试验证

### 文档完善
- T009: 更新 API 文档
- T010: 编写使用文档
- T011: 提供示例代码

## 4. 任务详情

### T001: 实现 NotificationGroup 类

**类型**: 核心实现
**依赖**: -

**files_write**:
- frameworks/ans/core/notification_group.h
- frameworks/ans/core/notification_group.cpp

**files_read**:
- frameworks/ans/core/notification_manager.h

**验收标准**:
- [ ] 类定义完整
- [ ] 基本方法实现
- [ ] 编译通过

**测试命令**:
```bash
./build.sh --product-name rk3568 --build-target distributed_notification_service
```

## 5. 测试用例清单

### 单元测试用例
| ID | 测试用例 | 覆盖功能 |
|----|----------|----------|
| UT-001 | NotificationGroup_GetId_00001 | GetId() |
| UT-002 | NotificationGroup_SetName_00001 | SetName() |

### 功能测试用例
| ID | 测试用例 | 场景 |
|----|----------|------|
| FT-001 | CreateGroup_00001 | 正常创建 |
| FT-002 | CreateGroup_00002 | 重复创建 |

## 6. 文档更新计划

| ID | 文档 | 更新内容 |
|----|------|----------|
| DOC-001 | API 文档 | 新增分组接口文档 |
| DOC-002 | 使用文档 | 分组功能使用说明 |
```

---

## 2. plan.md 结构化输出模板（JSON格式）

文件路径：`{kb_dir}/plan.md`（包含JSON结构化输出）

实际路径示例：`{kb_dir}/plan.md`

```json
{
  "dag": {
    "T001": [],
    "T002": ["T001"],
    "T003": ["T001"]
  },
  "tasks": {
    "T001": {
      "id": "T001",
      "name": "实现 NotificationGroup 类",
      "type": "core_implementation",
      "depends": [],
      "files_write": [
        "frameworks/ans/core/notification_group.h",
        "frameworks/ans/core/notification_group.cpp"
      ],
      "files_read": [
        "frameworks/ans/core/notification_manager.h"
      ],
      "acceptance_criteria": [
        "类定义完整",
        "基本方法实现",
        "编译通过"
      ],
      "test_commands": [
        "./build.sh --product-name rk3568 --build-target distributed_notification_service"
      ],
      "evidence_required": [
        "源代码文件",
        "编译日志",
        "单元测试代码（如有）"
      ],
      "risk_level": "low",
      "description": "实现 NotificationGroup 类，包含基本属性和方法"
    },
    "T002": {
      "id": "T002",
      "name": "实现分组创建接口",
      "type": "core_implementation",
      "depends": ["T001"],
      "files_write": [
        "frameworks/ans/core/notification_manager.cpp",
        "interfaces/inner_api/notification_manager_interface.h"
      ],
      "files_read": [
        "frameworks/ans/core/notification_group.h"
      ],
      "acceptance_criteria": [
        "接口定义完整",
        "实现逻辑正确",
        "单元测试覆盖"
      ],
      "test_commands": [
        "./build.sh --product-name rk3568 --build-target distributed_notification_service",
        "./build.sh --product-name rk3568 --build-target distributed_notification_service_test"
      ],
      "evidence_required": [
        "接口定义文档",
        "实现代码",
        "单元测试代码",
        "测试执行结果"
      ],
      "risk_level": "medium",
      "description": "在 NotificationManager 中实现分组创建接口"
    },
    "T003": {
      "id": "T003",
      "name": "实现分组查询接口",
      "type": "core_implementation",
      "depends": ["T001"],
      "files_write": [
        "frameworks/ans/core/notification_manager.cpp",
        "interfaces/inner_api/notification_manager_interface.h"
      ],
      "files_read": [
        "frameworks/ans/core/notification_group.h"
      ],
      "acceptance_criteria": [
        "接口定义完整",
        "实现逻辑正确",
        "单元测试覆盖"
      ],
      "test_commands": [
        "./build.sh --product-name rk3568 --build-target distributed_notification_service",
        "./build.sh --product-name rk3568 --build-target distributed_notification_service_test"
      ],
      "evidence_required": [
        "接口定义文档",
        "实现代码",
        "单元测试代码",
        "测试执行结果"
      ],
      "risk_level": "medium",
      "description": "在 NotificationManager 中实现分组查询接口"
    }
  }
}
```

---

## 3. tasks 字段说明

每个任务必须包含以下字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 任务唯一标识（如 T001） |
| `name` | string | 是 | 任务名称 |
| `type` | string | 是 | 任务类型：core_implementation / extended_features / test_validation / documentation |
| `depends` | array | 是 | 依赖的任务 ID 列表 |
| `files_write` | array | 是 | 可写文件路径列表（相对于工作区根目录） |
| `files_read` | array | 是 | 只读文件路径列表（相对于工作区根目录） |
| `acceptance_criteria` | array | 是 | 验收标准列表 |
| `test_commands` | array | 是 | 编译/测试命令列表 |
| `evidence_required` | array | 是 | 需要的证据产物列表 |
| `risk_level` | string | 是 | 风险等级：low / medium / high |
| `description` | string | 是 | 任务描述（供 Execute 参考） |

---

## 4. plan.md 溯源追踪矩阵章节模板

（Plan 文档末尾必须包含此章节，列出所有任务与开发设计文档的对齐关系）

文件路径：嵌入在 `{kb_dir}/plan.md` 中

```markdown
## 7. 溯源追踪矩阵

| 任务ID | 任务名称 | 开发设计引用 | 对齐状态 | 备注 |
|--------|---------|-------------|---------|------|
| T001 | 实现 NotificationGroup 类 | DEV-REF: 3.2 核心类设计 | ✅ 对齐 | |
| T002 | 实现分组创建接口 | DEV-REF: 5.1 公共接口 | ✅ 对齐 | |
| T003 | <任务> | [NEW] 开发设计未覆盖此任务 | ⚠️ 需确认 | <新增原因> |

**对齐统计**：
- 对齐项: <M>个
- 新增项（标注[NEW]）: <N>个
- 对齐率: M/(M+N) = <百分比>
- 新增项需经用户确认
```

---

## 5. plan.md 功能覆盖审计矩阵章节模板

（Plan 文档末尾必须包含此章节，确保开发设计文档中的所有功能点和场景都有对应任务覆盖）

文件路径：嵌入在 `{kb_dir}/plan.md` 中

```markdown
## 8. 功能覆盖审计矩阵

### 功能点提取清单
| FP-ID | 功能点/场景 | 来源（DEV-REF） | 必须覆盖 | 优先级 |
|-------|------------|-----------------|---------|--------|
| FP-001 | <场景> | DEV-REF: 4.1 核心流程 | 是 | 核心 |
| FP-002 | <场景> | DEV-REF: 4.3 异常处理 | 是 | 核心 |
| FP-003 | <场景> | DEV-REF: 5.1 公共接口 | 是 | 核心 |

### 任务-功能点覆盖映射
| FP-ID | 功能点 | 覆盖任务ID | 覆盖状态 | 备注 |
|-------|--------|-----------|---------|------|
| FP-001 | <场景> | T002, T003 | ✅ 已覆盖 | |
| FP-002 | <场景> | T004 | ✅ 已覆盖 | |
| FP-003 | <场景> | — | ❌ 未覆盖 | 需补充任务 |

### 覆盖统计
- 总功能点数: <N>
- 已覆盖: <M>
- 未覆盖（需补充）: <X>
- 刻意排除（标注 [EXCLUDED]）: <Y>
- 覆盖率: M/N = <百分比>%

要求：覆盖率必须达到 100%（未覆盖的功能点要么补充任务，要么标注 [EXCLUDED] 并经用户确认）
```
