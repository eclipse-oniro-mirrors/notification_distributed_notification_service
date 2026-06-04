# Dev-Design 阶段输出文件模板

本文件包含 Dev-Design Skill 产出的文件模板。

**重要约定**：
- 所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定
- `{name}`：需求/问题名称，用作目录名，英文小写字母，多个单词用 `-` 连接
- 模板中的路径需要替换为实际路径

---

## 1. context.md 输出文件模板

文件路径：`{kb_dir}/context.md`

实际路径示例：`{kb_dir}/context.md`

**生成时机**：Dev-Design 阶段由 Dev-Design Skill 生成

```markdown
# Context - 需求上下文

## 1. 需求名称
<name>

## 2. 需求描述
<详细的需求描述>

## 3. 入口文件
| 文件路径 | 类型 | 说明 |
|----------|------|------|
| <path1> | 入口 | <说明> |

## 4. 排除文件
| 文件路径 | 原因 |
|----------|------|
| <path1> | <原因> |

## 5. 验收标准列表
| ID | 验收标准 | 类型 | 功能点 |
|----|----------|------|--------|
| AC-001 | <标准> | 功能 | 功能点1 |
| AC-002 | <标准> | 性能 | 功能点2 |

## 6. 功能点列表
| ID | 功能点 | 优先级 | 验收标准 |
|----|--------|--------|----------|
| FP-001 | <功能点> | 核心 | AC-001 |
| FP-002 | <功能点> | 核心 | AC-002 |

## 7. 上下文约束
- 设计约束: <如有>
- 实现约束: <如有>
- 测试约束: <如有>
```

---

## 2. dev-design.md 输出文件模板

文件路径：`{kb_dir}/dev-design.md`

实际路径示例：`{kb_dir}/dev-design.md`

```markdown
# Dev-Design - 开发设计方案

## 1. 开发概述

### 1.1 功能实现概述
<从开发视角说明如何实现功能,包含具体的实现路径>

**实现路径**：
1. <步骤1>: <具体实现内容>
2. <步骤2>: <具体实现内容>
3. <步骤3>: <具体实现内容>

### 1.2 开发目标
- 目标1: <具体的开发目标说明>
- 目标2: <具体的开发目标说明>
- 目标3: <具体的开发目标说明>

### 1.3 开发约束
- 约束1: <具体的开发约束说明>
- 约束2: <具体的开发约束说明>
- 约束3: <具体的开发约束说明>

## 2. 开发架构设计

### 2.1 整体架构图
<使用 mermaid 表示架构图,包含具体的类和模块名称>

```mermaid
graph TD
    A[Client Layer] --> B[Service Layer]
    B --> C[Data Layer]
    ...
```

### 2.2 新增模块说明
| 模块名称 | 文件路径 | 说明 | 职责 |
|----------|----------|------|------|
| NotificationGroup | frameworks/ans/core/notification_group.h/cpp | 新增类 | 分组管理 |

### 2.3 扩展点说明
| 扩展点 | 现有文件 | 说明 | 扩展方式 |
|--------|----------|------|----------|
| NotificationManager接口 | interfaces/inner_api/notification_manager_interface.h | 公共接口 | 添加新方法 |

### 2.4 与现有架构集成方式
<说明具体的集成代码和集成步骤>

**集成步骤**：
1. <步骤1>: <具体的集成操作>
2. <步骤2>: <具体的集成操作>

## 3. 详细开发设计

### 3.1 类图
<使用 mermaid 表示类图,包含所有新增和修改的类>

```mermaid
classDiagram
    class NotificationGroup {
        +string id
        +string name
        +GetId() string
        +SetName(string) void
    }
    ...
```

### 3.2 核心类设计

#### NotificationGroup 类（新增）

**文件位置**: `frameworks/ans/core/notification_group.h` 和 `frameworks/ans/core/notification_group.cpp`

**类定义框架**:
```cpp
#include <string>
#include "parcel.h"

namespace OHOS {
namespace Notification {

class NotificationGroup : public Parcelable {
public:
    NotificationGroup();
    NotificationGroup(const std::string& id, const std::string& name);
    ~NotificationGroup();

    std::string GetId() const;
    std::string GetName() const;
    void SetName(const std::string& name);
    
    virtual bool Marshalling(Parcel& parcel) const override;
    static NotificationGroup* Unmarshalling(Parcel& parcel);

private:
    std::string id_;
    std::string name_;
};

}  // namespace Notification
}  // namespace OHOS
```

**实现要点**:
- 使用 `std::string` 存储分组 ID 和名称
- 继承 `Parcelable` 以支持 IPC 传输
- 实现 `Marshalling/Unmarshalling` 序列化方法
- ID 在构造时自动生成,使用 UUID 或时间戳

### 3.3 接口定义

#### 公共接口（新增）

**文件位置**: `interfaces/inner_api/notification_manager_interface.h`

**接口签名**:
```cpp
/**
 * @brief Creates a new notification group.
 * 
 * @param name The name of the group to create.
 * @param groupId Output parameter for the created group ID.
 * @return Returns ERR_OK on success, error code on failure.
 */
ErrCode CreateGroup(const std::string& name, std::string& groupId);

/**
 * @brief Gets all notification groups.
 * 
 * @param groups Output parameter for the list of groups.
 * @return Returns ERR_OK on success, error code on failure.
 */
ErrCode GetGroups(std::vector<NotificationGroup>& groups);

/**
 * @brief Deletes a notification group.
 * 
 * @param groupId The ID of the group to delete.
 * @return Returns ERR_OK on success, error code on failure.
 */
ErrCode DeleteGroup(const std::string& groupId);
```

**实现要点**:
- 所有接口返回 `ErrCode` 类型
- 使用输出参数返回结果数据
- 需要权限校验（使用 `PermissionHelper`）
- 需要参数校验（名称长度、ID 格式）

#### 内部接口（新增）

**文件位置**: `frameworks/ans/core/notification_group_manager.h`

**接口签名**:
```cpp
class NotificationGroupManager {
public:
    bool AddGroup(const sptr<NotificationGroup>& group);
    bool RemoveGroup(const std::string& groupId);
    sptr<NotificationGroup> GetGroup(const std::string& groupId);
    std::vector<sptr<NotificationGroup>> GetAllGroups();
    
private:
    std::map<std::string, sptr<NotificationGroup>> groups_;
};
```

### 3.4 数据结构定义

#### NotificationGroup 数据结构

**内存结构**:
```cpp
struct GroupData {
    std::string id;           // UUID 格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    std::string name;         // 分组名称,最大长度 64 字符
    int64_t createTime;       // 创建时间戳
    std::string creatorUid;   // 创建者 UID
};
```

**序列化格式**:
```cpp
// Marshalling 实现
bool NotificationGroup::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteString(id_)) {
        return false;
    }
    if (!parcel.WriteString(name_)) {
        return false;
    }
    if (!parcel.WriteInt64(createTime_)) {
        return false;
    }
    return parcel.WriteString(creatorUid_);
}
```

## 4. 开发流程设计

### 4.1 核心流程图
<使用 mermaid 表示流程图,包含具体的代码步骤>

```mermaid
graph TD
    A[Client 调用 CreateGroup] --> B{权限校验}
    B -->|失败| C[返回权限错误]
    B -->|成功| D{参数校验}
    D -->|失败| E[返回参数错误]
    D -->|成功| F[生成 GroupId]
    F --> G[创建 NotificationGroup 对象]
    G --> H[存储到 GroupManager]
    H --> I[持久化到数据库]
    I --> J[返回成功]
```

### 4.2 关键场景流程（含代码示例）

#### 创建分组场景

**代码步骤**:
```cpp
// Step 1: 权限校验
if (!PermissionHelper::VerifyPermission(token, "ohos.permission.NOTIFICATION_CONTROLLER")) {
    return ERR_ANS_PERMISSION_DENIED;
}

// Step 2: 参数校验
if (name.empty() || name.length() > MAX_GROUP_NAME_LENGTH) {
    return ERR_ANS_INVALID_PARAM;
}

// Step 3: 生成 GroupId
std::string groupId = GenerateUUID();

// Step 4: 创建对象
sptr<NotificationGroup> group = new NotificationGroup(groupId, name);

// Step 5: 存储
if (!groupManager_->AddGroup(group)) {
    return ERR_ANS_GROUP_ALREADY_EXISTS;
}

// Step 6: 持久化
if (!Preferences::GetInstance()->SaveGroup(group)) {
    ANS_LOGE("Failed to save group to preferences");
    // 不返回错误,因为内存已保存成功
}

return ERR_OK;
```

### 4.3 异常处理流程（含代码示例）

#### 权限错误处理

**代码示例**:
```cpp
ErrCode result = PermissionHelper::VerifyPermission(token, permission);
if (result != ERR_OK) {
    ANS_LOGE("Permission denied: %{public}d", result);
    return ERR_ANS_PERMISSION_DENIED;
}
```

#### 参数错误处理

**代码示例**:
```cpp
if (name.empty()) {
    ANS_LOGE("Group name is empty");
    return ERR_ANS_INVALID_PARAM;
}

if (name.length() > MAX_GROUP_NAME_LENGTH) {
    ANS_LOGW("Group name too long: %{public}zu", name.length());
    return ERR_ANS_INVALID_PARAM;
}
```

#### 存储失败处理

**代码示例**:
```cpp
if (!groupManager_->AddGroup(group)) {
    ANS_LOGE("Failed to add group: %{public}s", groupId.c_str());
    return ERR_ANS_GROUP_ALREADY_EXISTS;
}

// 持久化失败不影响内存操作
if (!Preferences::GetInstance()->SaveGroup(group)) {
    ANS_LOGW("Failed to save group to preferences, but memory save success");
}
```

## 5. 接口定义文档

### 5.1 公共接口定义

#### CreateGroup 接口

**完整定义**:
```cpp
/**
 * @brief Creates a new notification group.
 * @param name The name of the group (1-64 characters, non-empty).
 * @param groupId Output parameter for the created group ID (UUID format).
 * @return ERR_OK on success.
 * @return ERR_ANS_PERMISSION_DENIED if permission check fails.
 * @return ERR_ANS_INVALID_PARAM if name is invalid.
 * @return ERR_ANS_GROUP_ALREADY_EXISTS if group with same name exists.
 */
ErrCode CreateGroup(const std::string& name, std::string& groupId);
```

**调用示例**:
```cpp
std::string groupId;
ErrCode result = NotificationManager::CreateGroup("Important", groupId);
if (result == ERR_OK) {
    ANS_LOGI("Group created: %{public}s", groupId.c_str());
} else {
    ANS_LOGE("Failed to create group: %{public}d", result);
}
```

### 5.2 内部接口定义

#### GroupManager 内部接口

**完整定义**:
```cpp
class NotificationGroupManager {
public:
    /**
     * @brief Adds a group to the manager.
     * @param group The group to add.
     * @return true on success, false if group already exists.
     */
    bool AddGroup(const sptr<NotificationGroup>& group);
    
    /**
     * @brief Removes a group from the manager.
     * @param groupId The ID of the group to remove.
     * @return true on success, false if group not found.
     */
    bool RemoveGroup(const std::string& groupId);
    
    /**
     * @brief Gets a group by ID.
     * @param groupId The ID of the group to get.
     * @return The group object, nullptr if not found.
     */
    sptr<NotificationGroup> GetGroup(const std::string& groupId);
    
    /**
     * @brief Gets all groups.
     * @return Vector of all group objects.
     */
    std::vector<sptr<NotificationGroup>> GetAllGroups();

private:
    std::map<std::string, sptr<NotificationGroup>> groups_;
};
```

### 5.3 NAPI 接口定义（如需要）

#### JavaScript 接口绑定

**NAPI 实现示例**:
```cpp
static napi_value CreateGroupNapi(napi_env env, napi_callback_info info)
{
    // 获取参数
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    // 获取 name 参数
    std::string name;
    NapiUtils::GetStringValue(env, args[0], name);
    
    // 调用 C++ 接口
    std::string groupId;
    ErrCode result = NotificationManager::CreateGroup(name, groupId);
    
    // 返回结果
    napi_value ret;
    napi_create_object(env, &ret);
    NapiUtils::SetInt32Value(env, ret, "code", result);
    NapiUtils::SetStringValue(env, ret, "groupId", groupId);
    return ret;
}
```

**JavaScript 调用示例**:
```javascript
const result = await notificationManager.createGroup("Important");
if (result.code === 0) {
    console.log("Group created:", result.groupId);
}
```

### 5.4 接口兼容性说明

#### 新增接口兼容性

**兼容性处理**:
- 新增接口不影响现有接口
- 新增数据结构独立存储
- 新增功能需要权限申请

**兼容性检查代码**:
```cpp
// 版本检查
if (!IsFeatureSupported("NotificationGroup")) {
    ANS_LOGW("NotificationGroup feature not supported in this version");
    return ERR_ANS_FEATURE_NOT_SUPPORTED;
}
```

## 6. 开发测试策略

### 6.1 单元测试策略

#### 测试框架选择
- 使用 GoogleTest 框架
- 使用 HWTEST_F 宏定义测试用例
- 使用 EXPECT_EQ/ASSERT_EQ 进行断言

#### 测试命名规范
```cpp
HWTEST_F(NotificationGroupTest, GetId_00001, Function | SmallTest | Level1)
{
    // 测试用例命名: ClassName_MethodName_ScenarioNumber
}
```

#### 测试代码示例
```cpp
#define private public
#include "notification_group.h"
#undef private

HWTEST_F(NotificationGroupTest, CreateGroup_00001, Function | SmallTest | Level1)
{
    std::string name = "TestGroup";
    sptr<NotificationGroup> group = new NotificationGroup(name);
    
    EXPECT_NE(group, nullptr);
    EXPECT_FALSE(group->GetId().empty());
    EXPECT_EQ(group->GetName(), name);
}
```

### 6.2 功能测试策略

#### 正常场景测试
```cpp
HWTEST_F(NotificationGroupTest, CreateGroup_00001, Function | SmallTest | Level1)
{
    // 正常创建分组
    std::string groupId;
    ErrCode result = NotificationManager::CreateGroup("TestGroup", groupId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(groupId.empty());
}
```

#### 边界场景测试
```cpp
HWTEST_F(NotificationGroupTest, CreateGroup_00002, Function | SmallTest | Level1)
{
    // 名称长度边界
    std::string longName(65, 'a'); // 65 字符
    std::string groupId;
    ErrCode result = NotificationManager::CreateGroup(longName, groupId);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}
```

#### 异常场景测试
```cpp
HWTEST_F(NotificationGroupTest, CreateGroup_00003, Function | SmallTest | Level1)
{
    // 重复创建分组
    std::string groupId1, groupId2;
    NotificationManager::CreateGroup("TestGroup", groupId1);
    ErrCode result = NotificationManager::CreateGroup("TestGroup", groupId2);
    EXPECT_EQ(result, ERR_ANS_GROUP_ALREADY_EXISTS);
}
```

### 6.3 性能测试策略（如有性能要求）

#### 性能测试场景
```cpp
HWTEST_F(NotificationGroupTest, CreateGroupPerformance_00001, Performance | MediumTest | Level2)
{
    // 测试创建 100 个分组的性能
    int count = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < count; i++) {
        std::string groupId;
        NotificationManager::CreateGroup("Group" + std::to_string(i), groupId);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 1000); // 应小于 1 秒
}
```

### 6.4 测试覆盖目标

#### 覆盖率要求
- 单元测试覆盖率: ≥90% 分支覆盖率
- 功能测试覆盖率: 100% 正常场景 + 80% 异常场景
- 性能测试: 关键性能指标验证

#### 覆盖率检查命令
```bash
# 运行单元测试
./build.sh --product-name rk3568 --build-target distributed_notification_service_test

# 生成覆盖率报告
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

## 7. 开发要点说明

### 7.1 关键实现要点

#### 内存管理
```cpp
// 使用 sptr 管理对象生命周期
sptr<NotificationGroup> group = new NotificationGroup();

// 不要使用裸指针
// NotificationGroup* group = new NotificationGroup(); // 错误!
```

#### 线程安全
```cpp
// 使用 std::mutex 保护共享数据
std::lock_guard<std::mutex> lock(groupsMutex_);
groups_[groupId] = group;
```

#### 日志规范
```cpp
// 使用 ANS_LOG* 宏
ANS_LOGI("Group created: %{public}s", groupId.c_str());  // Info
ANS_LOGE("Failed to create group: %{public}d", result);  // Error

// 使用 %{public}s/d 格式化,确保日志可见
```

### 7.2 技术难点

#### IPC 序列化
**难点**: 需要正确实现 Parcelable 序列化

**解决方案**:
```cpp
// 确保所有字段都正确序列化
bool NotificationGroup::Marshalling(Parcel& parcel) const
{
    // 检查每个 WriteString/WriteInt 返回值
    if (!parcel.WriteString(id_)) {
        ANS_LOGE("Failed to write id");
        return false;
    }
    // ... 其他字段
    return true;
}

// Unmarshalling 时检查读取结果
NotificationGroup* NotificationGroup::Unmarshalling(Parcel& parcel)
{
    std::string id;
    if (!parcel.ReadString(id)) {
        ANS_LOGE("Failed to read id");
        return nullptr;
    }
    // ... 其他字段
    return new NotificationGroup(id, name);
}
```

#### 持久化处理
**难点**: 需要正确持久化分组数据

**解决方案**:
```cpp
// 使用 Preferences 持久化
void SaveGroupToPreferences(const sptr<NotificationGroup>& group)
{
    std::string key = "group_" + group->GetId();
    std::string value = SerializeGroup(group);
    
    if (!Preferences::GetInstance()->PutString(key, value)) {
        ANS_LOGE("Failed to save group");
    }
}
```

### 7.3 实现建议

#### 代码组织建议
- 新增类放在 `frameworks/ans/core/` 目录
- 新增接口放在 `interfaces/inner_api/` 目录
- 测试代码放在 `test/unittest/` 对应子目录

#### 命名规范建议
- 类名: PascalCase (NotificationGroup)
- 方法名: PascalCase (GetId, SetName)
- 变量名: camelCase (groupId, groupName)
- 常量: UPPER_SNAKE_CASE (MAX_GROUP_NAME_LENGTH)

#### 最佳实践建议
- 使用智能指针 (sptr/std::shared_ptr) 管理对象生命周期
- 使用 RAII 机制管理锁和资源
- 使用 ANS_LOG* 宏记录关键日志
- 使用 ErrCode 返回错误,避免抛出异常
- 实现 Parcelable 以支持 IPC 传输

## 8. 溯源追踪矩阵

（开发设计文档末尾必须包含此章节，列出所有设计决策与架构文档的对齐关系）

| 开发设计章节 | 架构决策引用 | 对齐状态 | 备注 |
|-------------|-------------|---------|------|
| 3.2 核心类设计 | ARCH-REF: 3.3 接口定义 (ARCH-DEC-001) | ✅ 对齐 | |
| 4.1 核心流程 | ARCH-REF: 3.1 业务流程 (ARCH-DEC-002) | ✅ 对齐 | |
| 5.1 公共接口 | ARCH-REF: 3.3 接口定义 (ARCH-DEC-001) | ✅ 对齐 | |
| 5.3 NAPI接口 | [NEW] 架构文档未提及NAPI绑定 | ⚠️ 需确认 | 需要NAPI层以支持JS调用 |

**对齐统计**：
- 对齐项: <M>个
- 新增项（标注[NEW]）: <N>个
- 对齐率: M/(M+N) = <百分比>
- 新增项需经用户确认
```