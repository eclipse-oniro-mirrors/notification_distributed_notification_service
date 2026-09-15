# 安全检视指南（security 维度）— code-check

## 规范来源

| 官方规范 | 本地路径（OpenHarmony 全仓工作区） | 线上地址 |
|---|---|---|
| OpenHarmony C&C++ 安全编程指南 | `docs/zh-cn/contribute/OpenHarmony-c-cpp-secure-coding-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-c-cpp-secure-coding-guide.md |
| OpenHarmony 安全设计规范 | `docs/zh-cn/contribute/OpenHarmony-security-design-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-security-design-guide.md |

> 本文件将上述官方规范**全量内化**为可执行检查项，并叠加 ANS（通知子系统）特化规则。
> 检视时逐项核对，每条发现必须给出 `file:line` + 触发路径证据。

---

## 第一部分：官方安全编程指南（全量检查项）

### 1. 函数

- [ ] **SEC-F01【规则】对所有外部数据进行合法性校验**
  外部数据包括：IPC 传入数据、跨设备（软总线）数据、文件/数据库读出数据、用户输入。
  校验时机：在数据进入的第一时间（函数入口/反序列化后）校验，而非使用点才校验。
  使用场景：作为循环条件/次数、内存申请大小、数组下标、字符串/格式化字符串、命令拼接时**必须**校验。

### 2. 类

- [ ] **SEC-C01【规则】类的成员变量必须显式初始化**（声明时或构造函数初始化列表），避免读取未初始化成员
- [ ] **SEC-C02【规则】明确需要实现哪些特殊成员函数**（三/五/零法则）：声明了析构/拷贝/移动之一，其余必须全部声明
- [ ] **SEC-C03【规则】基类中的拷贝构造、拷贝赋值、移动构造、移动赋值必须为非 public 或 delete**，防止对象切片
- [ ] **SEC-C04【规则】移动构造/移动赋值中必须将源对象资源正确重置**（指针置 nullptr），被移动对象须可正常析构
- [ ] **SEC-C05【规则】通过基类指针释放派生类时，基类析构函数必须为虚函数**（ANS 中 `Notification` 基类、`NotificationSubscriber` 回调接口均适用）
- [ ] **SEC-C06【规则】对象赋值或初始化避免切片操作**

### 3. 表达式与语句

- [ ] **SEC-E01【规则】确保对象在使用之前已被初始化**；多分支场景下所有分支都初始化后才能使用
- [ ] **SEC-E02【规则】避免使用 reinterpret_cast**（不相关类型转换）
- [ ] **SEC-E03【规则】避免使用 const_cast**（转换后修改 const 对象是未定义行为）
- [ ] **SEC-E04【规则】确保有符号整数运算不溢出**（溢出是 UB）：指针偏移、数组索引、内存复制长度、内存分配参数、循环条件中的有符号值必须校验
- [ ] **SEC-E05【规则】确保无符号整数运算不回绕**：同上场景的无符号值必须校验
- [ ] **SEC-E06【规则】确保除法和余数运算不会除零**：除数/模数为外部数据时必须先判非零
- [ ] **SEC-E07【规则】只能对无符号整数进行位运算**
  例外：作为位标志的有符号常量或枚举值可作 `&`/`|` 操作数；编译期可确定的有符号正整数可作移位右操作数。
  精度低于 int 的无符号整数位运算后必须立即转换为期望类型（避免整数提升）。

### 4. 资源管理

- [ ] **SEC-R01【规则】外部数据作为数组索引或内存操作长度时，必须校验合法性**（上限 + 下限 + 非空）
- [ ] **SEC-R02【规则】内存申请前必须对申请大小进行合法性校验**（size != 0 && size <= 上限）
- [ ] **SEC-R03【规则】传递数组参数时不应单独传递指针**（指针 + 长度成对传递）
- [ ] **SEC-R04【规则】lambda 逃逸出函数作用域时，禁止按引用捕获局部变量**（回调注册场景高发：异步回调捕获栈上引用 → 悬空）
- [ ] **SEC-R05【规则】指向资源句柄或描述符的变量，在资源释放后立即赋予新值**（置 nullptr）
- [ ] **SEC-R06【规则】new/delete 配对，new[]/delete[] 配对**
- [ ] **SEC-R07【规则】自定义 new/delete 操作符需配对定义，行为与被替换操作符一致**

### 5. 错误处理

- [ ] **SEC-H01【规则】抛异常时抛对象本身，不是指向对象的指针**
- [ ] **SEC-H02【规则】禁止从析构函数中抛出异常**
  ANS 补充：本仓默认不捕获 C++ 异常（第三方库如 nlohmann::json 的异常会直接 cppcrash），见第三部分 json 清单。

### 6. 标准库

- [ ] **SEC-S01【规则】禁止从空指针创建 std::string**（`std::string s(nullptr)` 是 UB）
- [ ] **SEC-S02【规则】不要保存 std::string 的 c_str()/data() 返回的指针**（string 修改/析构后悬空）
- [ ] **SEC-S03【规则】字符串操作缓冲区须有足够空间容纳字符数据和结束符**，字符串以 null 结束；不依赖 `'\0'` 判定边界前先确认数据带终止符
- [ ] **SEC-S04【规则】禁止使用 std::string 存储敏感信息**（string 内存不可控清除，敏感数据用后无法清零）
- [ ] **SEC-S05【规则】外部数据用于容器索引或迭代器时必须确保在有效范围内**（`vector[i]` 前校验 `i < size()`）
- [ ] **SEC-S06【规则】调用格式化输入/输出函数时使用有效的格式字符串**（格式符与实参类型匹配，ANS_LOG 宏的 `%{public}s`/`%{public}d` 与参数一一对应）
- [ ] **SEC-S07【规则】格式化函数的 format 参数禁止受外部数据控制**（外部数据只可作实参，不可拼入格式串）
- [ ] **SEC-S08【规则】禁止外部可控数据作为进程启动函数参数或 dlopen 等模块加载函数的参数**

### 7. C 语言专项

- [ ] **SEC-X01【规则】禁止对数组类型的函数参数变量进行 sizeof 获取数组大小**（已退化为指针）
- [ ] **SEC-X02【规则】禁止对指针变量 sizeof 获取数组大小**
- [ ] **SEC-X03【规则】禁止直接使用外部数据拼接 SQL 命令**（参数化查询）
- [ ] **SEC-X04【规则】内存中的敏感信息使用完毕后立即清 0**（memset_s）
- [ ] **SEC-X05【规则】创建文件时必须显式指定合适的文件访问权限**（禁用默认 umask 依赖）
- [ ] **SEC-X06【规则】使用文件路径前必须进行规范化并校验**（路径穿越：`..`、软链接、`/proc` 等；ANS 中通知附件/图片路径来自应用，必须校验）
- [ ] **SEC-X07【规则】不要在共享目录中创建临时文件**
- [ ] **SEC-X08【规则】不要在信号处理函数中访问共享对象**
- [ ] **SEC-X09【规则】禁用 rand() 产生安全用途的伪随机数**
- [ ] **SEC-X10【规则】禁止在发布版本中输出对象或函数的地址**
- [ ] **SEC-X11【规则】禁止代码中包含公网地址**

### 8. 内核安全编程

**N/A**：本仓为用户态子系统（SystemAbility + SDK），无内核态代码。若未来引入内核组件再补充。

---

## 第二部分：安全设计规范（6 领域，映射 ANS）

| 领域 | ANS 映射检查项 |
|---|---|
| 访问通道控制 | IPC 接口（`AnsManagerStub` 全部入口）必须有明确的权限策略：发布/订阅/偏好设置/勿扰/角标各接口的 `AccessTokenHelper` 校验是否完整；新增 IPC 入口是否同步新增权限校验；分布式通道（软总线）的设备认证 |
| 应用安全 | 通知发布方的身份校验（bundleName 与调用方 UID 一致性）；三方应用与系统应用的权限差异；NotificationSubscriber 回调注册的合法性 |
| 加密 | 分布式同步链路是否使用系统加密通道；不引入自研/弱加密算法（DES/MD5/SHA1 等）；密钥不硬编码 |
| 敏感数据保护 | 通知标题/内容/子文本 = 用户敏感数据：不落盘明文、不打 %{public} 日志、不进入无脱敏的事件；通知删除后内存及时清理 |
| 系统管理和维护安全 | dump 工具（`tools/`）输出是否包含敏感内容；调试接口是否有权限控制 |
| 隐私保护 | 通知内容跨设备同步前是否有授权确认（分布式授权变更场景）；用户关闭同步后残留数据清理 |

---

## 第三部分：ANS 特化安全检视

### 3.1 权限校验位置（对应 ANS 陷阱 A5，全集定义见 [ans-pitfalls.md](ans-pitfalls.md)）

**架构不变量：权限校验必须在服务端能力入口完成，不能仅依赖客户端。**

- [ ] 新增/修改的 IPC 接口在 `services/ans/`（`AdvancedNotificationService` / `AnsManagerStub` 实现）入口处是否有权限校验
- [ ] 权限校验使用 `AccessTokenHelper`（`services/ans/include/access_token_helper.h`）+ 过滤器（`permission_filter.h`），不得仅凭 TokenType 类型判断绕过
- [ ] `frameworks/`（客户端 SDK）中的校验只能作为提前失败优化，不能作为唯一防线
- [ ] 代理/回调接口（`IAnsSubscriber` 等反向 IPC）也要校验调用方身份

### 3.2 IPC 输入校验

所有经 `frameworks/ans` Parcelable 反序列化进入服务端的数据（`Notification`、`NotificationRequest`、bundleName、slot、userId 等）**来自不可信客户端**：

- [ ] 字符串字段：判空 + 长度上限（防超大内存消耗）
- [ ] 数值字段：范围校验（userId 合法域、枚举值有效性）
- [ ] 容器字段：元素数量上限（防超大数组，序列化时校验）
- [ ] 图片/像素图数据：大小上限 + 路径校验（见 SEC-X06）
- [ ] 循环次数受外部数据控制时必须校验合法性

### 3.3 nlohmann::json 使用安全（本仓 cppcrash 历史教训，全量内化）

> nlohmann::json 多个接口（`parse`/`at`/`get<T>`/`operator[]`）在类型或存在性不匹配时抛 C++ 异常，
> 本仓默认不捕获，抛出即 cppcrash。凡涉及 json 用法的变更，必须逐项核对。

| 编号 | 检查项 |
|---|---|
| SEC-J01 (P0) | 所有 `parse()` 是否用 `nullptr, false`（不抛异常模式）或前置 `accept()`，无裸 `parse(str)` |
| SEC-J02 (P0) | 所有 `at(key)` 前是否有 `find(key)` / `contains(key)` |
| SEC-J03 (P0) | 链式 `operator[][]` 是否逐层 `is_object()` 校验 |
| SEC-J04 (P0) | 标量 `get<T>()` 前是否有对应 `is_xxx()`；取 int32/uint32 必须用 `is_number_integer()`（**禁止 `is_number()`**：含 float，大浮点/NaN/Inf 取 int 抛 `out_of_range` 崩溃）+ `get<int64_t>()` + 值域校验后窄化 |
| SEC-J05 (P0) | `get<vector<T>>()` / `get<set<T>>()` 是否遍历逐元素校验（**禁止仅 `is_array()` 后直接 get**） |
| SEC-J06 (P0) | 遍历中 `iter.value().get<T>()` / `item.get<T>()` 前是否 `is_xxx()` 校验 |
| SEC-J07 (P1) | `front()` / `back()` 前是否 `!empty()` |
| SEC-J08 (P1) | 整数下标 `arr[i]` 前是否 `i < size()` 校验 |
| SEC-J09 (P2) | `dump()` 是否传 `error_handler_t::replace` |

### 3.4 跨设备数据不可信

`services/distributed/`（软总线链路）收到的数据来自**其他设备**，可能版本更旧/更新或被篡改：

- [ ] TLV/分布式数据解析前校验长度与版本（版本不匹配场景必须安全降级，不能崩溃或行为异常）
- [ ] 对端通知数据按不可信输入处理（同 3.2）
- [ ] 授权变更后对端数据立即失效（不能继续处理旧授权的数据）

### 3.5 敏感信息

- [ ] 通知标题/内容/子文本打日志必须 `%{private}`（ANS_LOG 宏 `{private}` 修饰）
- [ ] 禁止 HiSysEvent 事件参数携带通知明文内容
- [ ] 禁止硬编码密钥/密码/Token（`password`、`secret`、`key` 检索）
- [ ] 禁止日志打印内存地址（配合 SEC-X10）

---

## 检测命令

```bash
# 注意：必须用 `grep -rn "pattern" --include="*.cpp" --include="*.h" <dir>` 形式递归搜索，
# 并排除非维护目录
EXCLUDE="--exclude-dir=reminder --exclude-dir=cj --exclude-dir=reminder_ani"

# 危险函数
grep -rn "strcpy\b\|sprintf\b\|strcat\b" --include="*.cpp" --include="*.h" . $EXCLUDE   # SEC-S03/X 系
grep -rn "\bmemcpy\b" --include="*.cpp" --include="*.h" . $EXCLUDE                      # 应使用 memcpy_s
grep -rn "rand()\|srand(" --include="*.cpp" --include="*.h" . $EXCLUDE                  # SEC-X09

# 类型转换
grep -rn "reinterpret_cast\|const_cast" --include="*.cpp" --include="*.h" . $EXCLUDE    # SEC-E02/E03

# 敏感信息
grep -rn "password\|secret\|token" --include="*.cpp" --include="*.h" . $EXCLUDE | grep -v "AccessToken\|SecurityToken" # 人工复核

# json 安全（见 3.3）
grep -rn "json::parse(" --include="*.cpp" --include="*.h" . $EXCLUDE                    # SEC-J01
grep -rn "is_number()" --include="*.cpp" --include="*.h" . $EXCLUDE                     # SEC-J04 危险用法
grep -rn "get<std::vector\|get<std::set" --include="*.cpp" --include="*.h" . $EXCLUDE   # SEC-J05
grep -rn "\.front()\|\.back()" --include="*.cpp" --include="*.h" . $EXCLUDE             # SEC-J07

# 公网地址
grep -rnE "([0-9]{1,3}\.){3}[0-9]{1,3}" --include="*.cpp" --include="*.h" . $EXCLUDE | grep -v "127.0.0.1\|0.0.0.0\|version" # SEC-X11

# 客户端违规打点（架构红线，详见 dfx-review.md；排除非维护目录）
grep -rn "HiSysEventWrite\|SendHiSysEvent\|EventReport::" frameworks/ interfaces/ --include="*.cpp" --include="*.h" $EXCLUDE # 应为空
```

---

## 严重等级映射

| 检查项类别 | 默认等级 |
|---|---|
| 内存安全（溢出/UAF/悬空/未初始化/泄漏）、json 异常崩溃、IPC 输入未校验、权限缺失 | **P0** |
| 类型转换、整数运算、敏感信息 %{public}、跨设备数据未校验、lambda 捕获 | **P1** |
| 防御性编程缺失、SQL/路径校验、 rand 使用 | **P2** |
| 风格性安全建议 | **P3** |

## 输出格式

发现以 `SEC-xxx` 编号输出（见 report-template.md 问题编号规则），每条包含：位置（file:line）、触发路径、影响、证据、规范依据（引用 SEC-XX 编号）、建议。原始产出保存至 `.codecheck/raw/security.md`。
