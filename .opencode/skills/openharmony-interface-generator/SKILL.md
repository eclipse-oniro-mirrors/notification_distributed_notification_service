---
name: openharmony-interface-generator
description: "为 OpenHarmony 通知服务生成符合项目规范的 JS/TS/ArkTS 接口声明和示例代码。当需要声明新接口、编写接口示例代码、设计 NAPI 绑定、添加通知服务公共 API 时使用。自动触发于涉及接口声明、API 定义、NAPI 绑定或通知服务公共 API 的任何任务。"
---

# OpenHarmony 接口生成器

## 概述

为 OpenHarmony 通知服务生成符合项目规范的 JS/TS/ArkTS 接口声明和示例代码。**核心方法：通过研究现有实现学习最佳实践，确保新接口与项目风格一致。**

## 核心流程

### 步骤 1：研究现有实现

在声明任何新接口之前，**必须**研究现有实现。

**参考资源（可直接通过 webfetch 读取）：**

| 类型 | URL |
|------|-----|
| Manager API | https://raw.gitcode.com/openharmony/interface_sdk-js/raw/master/api/@ohos.notificationManager.d.ts |
| Subscribe API | https://raw.gitcode.com/openharmony/interface_sdk-js/raw/master/api/@ohos.notificationSubscribe.d.ts |
| Extension API | https://raw.gitcode.com/openharmony/interface_sdk-js/raw/master/api/@ohos.notificationExtensionSubscription.d.ts |
| 数据结构 | https://gitcode.com/openharmony/interface_sdk-js/tree/master/api/notification |
| API 文档（中文） | https://gitcode.com/openharmony/docs/tree/master/zh-cn/application-dev/reference/apis-notification-kit |

**获取方法：**
- **文件链接**：使用 `webfetch` 工具获取 raw 链接文件内容
- **目录链接**：使用 sparse clone 方式获取目录内容：
  ```bash
  git clone --depth 1 --filter=blob:none --sparse <repo_url> /tmp/opencode/<repo_name>
  cd /tmp/opencode/<repo_name> && git sparse-checkout set <目录路径>
  ```
- 委托 `@explore` 子代理进行综合分析，提取下面步骤所需的模式和规范

### 步骤 2：提取模式并生成接口

从现有实现中提取关键模式，应用到新接口。

**关键规则：**

| 规则类型 | 说明 | 示例 |
|---------|------|------|
| 命名 | Manager 接口 → `@ohos.notification<Name>.d.ts` | `@ohos.notificationManager.d.ts` |
| 方法名 | 动词开头，批量操作加 All 后缀 | `publish`, `cancelAll` |
| 注解 | 必需：`@since`, `@syscap`, `@returns`；可选：`@throws` | 见下方模板 |
| 参数注解 | 格式：`{ Type } name - 描述` | `{ NotificationRequest } request - 通知请求` |
| 错误码 | 201（权限）、401（参数）、1600001（内部） | `@throws { BusinessError } 201 - 权限校验失败` |
| 结构 | 属性直接声明；构造函数无参/必需参数；链式方法返回 this | 见数据结构模板 |
| 异步 | 须向用户确认具体的异步实现方式：callback（可选） + promise | 见异步模板 |

### 步骤 3：验证一致性

对比新接口与现有接口，确保风格一致。

| 检查项 | 对比方法 |
|--------|----------|
| 命名一致性 | 与现有同类接口对比命名风格 |
| 注解完整性 | 与现有接口对比注解种类和格式 |
| 类型一致性 | 与现有类似方法对比参数/返回类型 |
| 示例风格 | 与现有文档示例对比结构 |

## 常见接口类型参考

| 接口类型 | 参考文件 |
|----------|----------|
| Manager 接口 | @ohos.notificationManager.d.ts |
| Subscribe 接口 | @ohos.notificationSubscribe.d.ts |
| Extension 接口 | @ohos.notificationExtensionSubscription.d.ts |
| 数据结构 | notification/notificationRequest.d.ts |
| 枚举类型 | notification/slotType.d.ts |

## 输出要求

**接口声明：**
- 接口/类完整声明
- 所有必需注解（@since, @syscap, @returns, @throws）
- 类型定义（参考现有类型）
- 错误定义（使用现有错误码）

**示例代码：**
- import 语句（参考现有示例）
- 使用示例（参考 API 文档风格）
- 错误处理（try-catch + .then/.catch）
- 日志输出（console.info/error + JSON.stringify）

## 质量检查

完成接口前检查：
- [ ] 已研究至少 2 个现有类似接口
- [ ] 命名、注解、类型与现有接口一致
- [ ] 示例代码风格与现有文档一致