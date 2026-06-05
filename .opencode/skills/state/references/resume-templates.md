# Resume 续跑流程汇报模板

本文件包含工作流续跑时的汇报模板。

---

## Resume 续跑流程汇报模板

```text
[RESUME] 检测到未完成的流程:
- 当前阶段: <phase_name>
- 当前状态: <status>
- 阻塞原因: <如果被阻塞>

已有阶段文档:
- architecture.md: <存在/不存在> (状态: <done/pending>)
- dev-design.md: <存在/不存在> (状态: <done/pending>)
- context.md: <存在/不存在>
- plan.md: <存在/不存在> (状态: <done/pending>)

若阻塞点为用户确认门:
- 等待批准的文档: <document_path>
- 请回复"批准"或"需要修改"以继续流程

若为正常进行中:
- 将读取已有文档，从断点处继续执行
```