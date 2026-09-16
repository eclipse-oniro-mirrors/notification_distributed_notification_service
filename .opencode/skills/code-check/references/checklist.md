# 规范检视指南（checklist 维度）— code-check

## 规范来源

| 官方规范 | 本地路径（OpenHarmony 全仓工作区） | 线上地址 |
|---|---|---|
| OpenHarmony C++语言编程规范 | `docs/zh-cn/contribute/OpenHarmony-cpp-coding-style-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-cpp-coding-style-guide.md |
| OpenHarmony 32/64位可移植编程规范 | `docs/zh-cn/contribute/OpenHarmony-64bits-coding-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-64bits-coding-guide.md |
| OpenHarmony 编译规范 | `docs/zh-cn/contribute/OpenHarmony-compile-rule.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-compile-rule.md |
| OpenHarmony 开源构建规范 | `docs/zh-cn/contribute/OpenHarmony-build-rule.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-build-rule.md |
| 许可证与版权规范 | `docs/zh-cn/contribute/许可证与版权规范.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/许可证与版权规范.md |
| 贡献代码 / 贡献流程 | `docs/zh-cn/contribute/贡献代码.md`、`贡献流程.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/贡献代码.md |
| TS&JS 编程指南 | `docs/zh-cn/contribute/OpenHarmony-Application-Typescript-JavaScript-coding-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-Application-Typescript-JavaScript-coding-guide.md |

> 本文件将上述官方规范内化为可勾选检查项（括号内为官方规则编号，便于回溯权威源）。
> 适用范围：`frameworks/`、`services/`、`interfaces/`、`tools/` 下 C++/ArkTS 代码；
> **排除非维护目录**：`frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/`。
> C 语言规范（`OpenHarmony-c-coding-style-guide.md`）、HDF/Java 规范：**N/A**（本仓无对应代码形态）。

---

## 第一部分：C++ 编程规范（规则编号溯源）

### 1. 命名

- [ ] CHK-N01 文件名统一小写 + 下划线，禁止大小写混用与 `-` 分隔（建议1.2/规则2.2.1）
- [ ] CHK-N02 `.cpp` 与 `.h` 成对，文件名与类名一致（规则2.2.1/2.2.2）
- [ ] CHK-N03 函数/类/命名空间大驼峰；动宾结构命名动作函数，`Is/Has` 前缀判断函数（规则2.3）
- [ ] CHK-N04 全局变量 `g_` 前缀；静态变量不加特殊前缀（规则2.5.1）
- [ ] CHK-N05 类成员变量小驼峰 + 后下划线（如 `bundleName_`）（规则2.5.2）
- [ ] CHK-N06 宏/枚举值/全局常量全大写下划线连接；函数局部 const 与普通 const 成员小驼峰（规则2.6）
- [ ] CHK-N07 避免对基本类型滥用 typedef/#define 起别名（建议2.4.1）

### 2. 格式

- [ ] CHK-F01 行宽 ≤ 120 字符；例外：长 URL 注释、长 #include 路径（规则3.1.1）
- [ ] CHK-F02 4 空格缩进，禁止 Tab（规则3.2.1）
- [ ] CHK-F03 K&R 大括号风格：函数左大括号另起一行；if/for/while 左大括号随语句行末（规则3.3.1）
- [ ] CHK-F04 函数声明与定义的返回类型和函数名同行；超行宽换行对齐（规则3.4.1）
- [ ] CHK-F05 函数调用入参超行宽换行时参数合理对齐（规则3.5.1）
- [ ] CHK-F06 if/for/while 必须使用大括号，即使单条语句（规则3.6.1/3.7.1）
- [ ] CHK-F07 禁止 if/else/else if 写在同一行（规则3.6.2）
- [ ] CHK-F08 switch 的 case/default 缩进一层（规则3.8.1）
- [ ] CHK-F09 表达式换行运算符放行末，保持对齐或 4 空格缩进（建议3.9.1）
- [ ] CHK-F10 多个变量定义/赋值不写在一行（规则3.10.1）
- [ ] CHK-F11 指针 `*` / 引用 `&` 靠变量名或类型，风格一致（建议3.12.1/3.12.2）
- [ ] CHK-F12 预处理 `#` 放行首；嵌套时可缩进（规则3.13.1）
- [ ] CHK-F13 空格规则：关键字后加空格、小括号内侧不加、二元运算符两侧加、一元运算符后不加、行尾不留空格（规则3.14.1）
- [ ] CHK-F14 空行规则：无 3 连空行、大括号内侧首尾不加空行（建议3.14.1）
- [ ] CHK-F15 类访问控制块 public → protected → private 顺序，缩进与 class 对齐（规则3.15.1）
- [ ] CHK-F16 构造函数初始化列表同行或 4 空格缩进多行（规则3.15.2）

### 3. 注释

- [ ] CHK-D01 文件头注释必须含版权许可声明（规则4.2.1），新增文件版权年份为当前年份
- [ ] CHK-D02 公有函数必须写函数头注释，禁止空有格式的注释（规则4.3.1/4.3.2）
- [ ] CHK-D03 注释符与内容间 1 空格，右置注释与代码 ≥1 空格，与代码同缩进
- [ ] CHK-D04 使用英文注释

### 4. 头文件

- [ ] CHK-I01 头文件自包含（self-contained，单独 include 可编译）
- [ ] CHK-I02 禁止重复包含；使用 `#ifndef` 头文件保护
- [ ] CHK-I03 Include 顺序：对应头文件 → 模块内头文件 → OpenHarmony 系统头文件 → 第三方 → 标准库
- [ ] CHK-I04 头文件中不定义变量/函数实现（inline 除外）

### 5. 作用域与命名空间

- [ ] CHK-SC01 代码位于 `OHOS::Notification` 命名空间内（ANS 仓约定）
- [ ] CHK-SC02 禁止 using namespace 污染头文件
- [ ] CHK-SC03 优先命名空间内非成员函数/静态成员，避免全局函数

### 6. 类设计

- [ ] CHK-CL01 单参数构造函数声明 explicit
- [ ] CHK-CL02 虚函数重写声明 override
- [ ] CHK-CL03 三/五/零法则（详见 security-review.md SEC-C02）
- [ ] CHK-CL04 成员声明顺序建议：类型 → 常量 → 工厂 → 构造/赋值/析构 → 成员函数 → 数据成员

### 7. 函数

- [ ] CHK-FU01 函数单一职责，建议 ≤100 行（超长函数需检视拆分）
- [ ] CHK-FU02 参数建议 ≤5 个，避免 bool 标志参数（用枚举表达语义）

### 8. C++ 特性

- [ ] CHK-CP01 避免 long 类型（见第二部分 64 位规范）；使用 `int32_t`/`uint32_t` 等固定宽度类型
- [ ] CHK-CP02 禁用 C 风格强制转换 `(T*)`，使用 static_cast 等 C++ 转换
- [ ] CHK-CP03 资源管理 RAII；优先智能指针（ANS 中跨进程对象用 `sptr`，进程内可用 `std::shared_ptr`）
- [ ] CHK-CP04 使用 `nullptr`，禁止 `NULL`
- [ ] CHK-CP05 禁止使用宏表示常量、函数式宏（规则3.13.3/3.13.4；例外：日志宏需保留 `__FILE__`/`__LINE__`）

---

## 第二部分：32/64 位可移植规范

- [ ] CHK-B01 使用固定宽度类型 `int8_t`…`int64_t`；**禁止** `long`/`int`/`short`/`size_t` 定义对外存储或通信的数据
- [ ] CHK-B02 禁止 `uchar`/`unsigned char` 定义字符串（用 `char` 或 `uint8_t` 明确语义）
- [ ] CHK-B03 存储指针的整数用 `uintptr_t`（禁止 `long`/`int` 强转指针）
- [ ] CHK-B04 指针与 int32/int64 混合运算注意符号扩展：跨宽度运算先将操作数转换为 64 位
- [ ] CHK-B05 64 位类型格式化输出使用 `PRId64`/`PRIu64` 或对应宽度格式符，与 `ANS_LOG` 参数匹配
- [ ] CHK-B06 结构体对齐：跨进程/跨设备传输的结构避免依赖默认对齐（显式 pack 或固定宽度成员）

---

## 第三部分：编译与构建规范

### BUILD.gn 检查

- [ ] CHK-G01 所有 `ohos_shared_library`/`ohos_source_set`/`ohos_executable` 等编译目标开启 PAC 保护：`branch_protector_ret = "pac_ret"`
- [ ] CHK-G02 栈保护：C/C++ 目标启用 `-fstack-protector-strong`（编译规范 G.C&C++.SEC.01）
- [ ] CHK-G03 警告选项：不新增屏蔽告警（`-w`/`-Wno-*` 需说明理由）；不因告警删除诊断代码
- [ ] CHK-G04 新增依赖必须在对应部件许可清单内，禁止引入未确认的生产依赖
- [ ] CHK-G05 GN 编写规范：source_set/module 名唯一、part_name 与子系统声明一致（构建规范）

### 版本脚本检查

- [ ] CHK-G06 禁止修改 `*.map`（`interfaces/ndk/libohnotification.map`、`frameworks/js/napi/*.map`、`frameworks/ets/ani/*.map`）中已有符号的可见性——**门禁红线，违者 P0**

---

## 第四部分：版权与许可头（许可证与版权规范）

- [ ] CHK-L01 新增源文件（.cpp/.h）必须包含 Apache License 2.0 许可头 + 版权行：
  ```
  Copyright (C) [第一次发布年份]-[当前版本发布年份] [版权所有者]
  ```
  首次发布只写发布年份；非首次写"首年-当前年"（当前年份必须是本次提交年份）
- [ ] CHK-L02 版权所有者为法律实体（代表公司贡献写公司实体名）
- [ ] CHK-L03 例外可不加版权头：JSON 等不支持注释的格式、工具自动生成文件、README 类短说明
- [ ] CHK-L04 引入第三方代码片段须保留原版权与许可头，并在 LICENSE/NOTICE 机制下声明（新依赖需走引入评审）

## 第五部分：贡献规范（贡献代码/贡献流程）

- [ ] CHK-V01 提交签署 DCO（`git commit -s`，signed-off-by 存在）
- [ ] CHK-V02 commit message 规范：主题行简明描述变更，正文说明动机与影响，关联 issue
- [ ] CHK-V03 涉及安全敏感领域（权限、加密、IPC 输入处理）的变更应在 PR 描述中显式标注，便于安全检视
- [ ] CHK-V04 不提交调试用途的临时代码（打印变量、注释掉的功能代码、TODO 无跟踪单）
- [ ] CHK-V05 不提交与本次变更无关的文件（混入的格式化改动、个人配置）

---

## 第六部分：TS&JS（ArkTS）轻量规范

> 适用：`frameworks/js/`、`frameworks/ets/`、`interfaces/kits/napi/`、`services/dialog_ui/` 中的 .ets/.ts 代码。

- [ ] CHK-T01 使用严格模式（默认模块即严格）
- [ ] CHK-T02 禁止使用 `eval()`
- [ ] CHK-T03 禁止使用 `with() {}`
- [ ] CHK-T04 不动态创建函数（`new Function(...)`）
- [ ] CHK-T05 声明变量使用 const/let，禁止 var
- [ ] CHK-T06 浮点数字面量不省略小数点前后 0（`.5` / `5.` 禁止）
- [ ] CHK-T07 禁止修改内建对象原型
- [ ] CHK-T08 相等比较使用 `===`/`!==`
- [ ] CHK-T09 switch 必须有 default（或穷尽枚举断言）
- [ ] CHK-T10 异步操作必须处理 reject 路径（Promise catch / try-catch）

---

## 第七部分：ANS 通用陷阱

- [ ] **CHK-P01 SA 初始化禁阻塞禁失败**：`AdvancedNotificationServiceAbility::OnStart()` 及初始化路径禁止同步文件 IO、等待其他 SA、复杂计算；启动必须成功（失败会导致系统通知能力缺失）
- [ ] **CHK-P02 数据一致性（内存 ↔ RDB）**：偏好设置（`notification_preferences*.cpp`）修改顺序为内存 → 持久化（`services/infrastructure/external_adapter/rdb`）；失败路径必须回滚内存态，不能留下不一致
- [ ] **CHK-P03 RDB schema 变更须跨版本兼容**：升级路径（旧版本数据迁移）必须在设计中明确并配套测试
- [ ] **CHK-P04 错误码处理完整**：所有可失败调用检查返回值（ErrCode）；错误向上传递不吞掉；HILOG 流控会修改 errno——调用日志宏后不得立即使用 errno
- [ ] **CHK-P05 特性开关条件编译完整**：`notification.gni` 开关（`distributed_notification_service_feature_*`、`hisysevent_usage`、`ans_hitrace_usage`、`standby_enable` 等）包裹的代码在 on/off 两种配置下都必须可编译（新增开关须双路径验证）
- [ ] **CHK-P06 禁止删除日志/事件/错误码**：为通过测试而删除 DFX 诊断信息是门禁红线
- [ ] **CHK-P07 禁止修改 IDL 生成的 proxy/stub 代码**：应修改 `frameworks/ans/*.idl` 源文件后重新生成

## 第八部分：变更范围红线（对应 ANS 陷阱 A8，全集定义见 [ans-pitfalls.md](ans-pitfalls.md)）

- [ ] **CHK-R01 非维护目录禁改**：以下目录由其他团队维护，出现任何改动即 P0 上报，不进入后续检视：
  `frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/`
- [ ] CHK-R02 不绕过现有 DFX/安全/兼容性检查（删除断言、跳过权限校验路径以通过测试等）

---

## 检测命令

```bash
EXCLUDE="--exclude-dir=reminder --exclude-dir=cj --exclude-dir=reminder_ani"

# 命名/格式快速扫描
grep -rn "\bNULL\b" --include="*.cpp" --include="*.h" . $EXCLUDE                # CHK-CP04
grep -rn "\blong\b" --include="*.cpp" --include="*.h" . $EXCLUDE | grep -v "long long\|along\|belong" # CHK-B01 人工复核
grep -rn "\(\w+\*\)" --include="*.cpp" --include="*.h" . $EXCLUDE               # C 风格转换 CHK-CP02
find services frameworks interfaces tools \( -name "*.cpp" -o -name "*.h" \) -print0 | grep -zvE "reminder|/cj/" | xargs -0 awk 'length > 120 {print FILENAME":"FNR}' # CHK-F01

# 版权头（新增文件）
git diff --name-only --diff-filter=A HEAD | grep -E "\.(cpp|h)$" | xargs -I{} sh -c 'head -5 "{}" | grep -q "Apache License" || echo "MISSING LICENSE: {}"'

# BUILD.gn PAC
grep -rL "branch_protector_ret" --include="BUILD.gn" services frameworks tools | while read f; do grep -q "ohos_shared_library\|ohos_source_set\|ohos_executable" "$f" && echo "NO PAC: $f"; done

# .map 变更（红线检测）
git diff HEAD --name-only | grep "\.map$" && echo "WARN: .map 文件被修改，核对符号可见性是否改变"

# 非维护目录变更（红线检测）
git diff HEAD --name-only | grep -E "^(frameworks/cj/|frameworks/reminder/|frameworks/reminder_ani/|services/reminder/)" && echo "P0: 非维护目录被修改"
```

## 严重等级映射

| 类别 | 默认等级 |
|---|---|
| .map 符号可见性修改、非维护目录修改、删除 DFX 诊断、绕过安全检查 | **P0** |
| 版权头缺失/年份错误、宏常量、long 类型用于 IPC 数据、PAC 缺失 | **P1** |
| 命名/格式/注释/风格违规、TS/JS 规范 | **P2** |
| 建议性优化 | **P3** |

## 输出格式

发现以 `CHK-xxx` 编号输出（见 report-template.md），每条包含：位置、问题、规范依据（CHK 编号 + 官方规则号）、修复建议。原始产出保存至 `.codecheck/raw/checklist.md`。
