# 测试覆盖检视指南（test 维度）— code-check

## 规范来源

| 官方规范 | 本地路径 | 线上地址 |
|---|---|---|
| OpenHarmony 安全测试规范 | `docs/zh-cn/contribute/OpenHarmony-security-test-guide.md` | https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/OpenHarmony-security-test-guide.md |

---

## 测试资产地图（仓内事实）

| 资产 | 位置 | 说明 |
|---|---|---|
| 子系统级测试 | `test/unittest`、`test/fuzztest`、`test/systemtest`、`test/bechmarktest`、`test/mock` | 子系统聚合测试目录 |
| 模块级单测 | `services/ans/test/unittest` 等各模块 `test/` 目录 | 服务端核心模块单测 |
| 构建目标 | `distributed_notification_service_unit_test` / `distributed_notification_service_fuzz_test` | 从 OpenHarmony 根目录构建 |
| 测试宏 | HWTEST_F / HWTEST（OpenHarmony 测试框架） | 全项目测试代码统一使用 |

构建命令（无法在本技能内执行时给出建议命令）：

```bash
./build.sh --product-name rk3568 --build-target distributed_notification_service_unit_test
./build.sh --product-name rk3568 --build-target distributed_notification_service_fuzz_test
```

---

## 检查清单

### 1. 变更—测试映射（核心检查）

- [ ] **TEST-01 新代码有测试**：每个新增/修改的行为单元（新函数、新分支、新状态转换）在对应 `test/unittest` 有覆盖用例；**无任何测试配套的行为变更**是本维度主要发现
- [ ] **TEST-02 测试位置正确**：`services/ans` 变更 → `services/ans/test/unittest`；`services/distributed` 变更 → 对应模块测试目录
- [ ] **TEST-03 测试与实现同步修改**：行为变更后旧用例断言已更新（不是直接改断言迁就新行为——需核对断言变化与需求一致，与功能维度联动）
- [ ] **TEST-04 BUILD.gn 已挂载**：新增测试文件已在对应测试 BUILD.gn 注册，否则不被编译执行

### 2. 用例质量

- [ ] **TEST-05 断言有效性**：断言验证行为结果而非"不崩溃"（`EXPECT_EQ(ret, ERR_OK)` + 状态检查，而非只 `EXPECT_TRUE`）
- [ ] **TEST-06 边界与错误路径**：成功 + 失败 + 边界（空输入、超限、权限拒绝）三类都有用例；错误路径测试与 DFX 联动（错误发生时事件已上报）
- [ ] **TEST-07 mock 使用规范**：外部依赖（DB/分布式/其他 SA）用 `test/mock` 桩替代；mock 行为与真实接口契约一致（mock 迁就实现是反模式）
- [ ] **TEST-08 测试独立性**：用例间无顺序依赖、无共享可变状态；每用例自清理（订阅注销、通知清空）

### 3. 覆盖标准

- [ ] **TEST-09 分支覆盖**：新增/修改代码分支覆盖率达到 90%（项目标准）；未覆盖分支逐个列出并说明原因（不可达/后续补）
- [ ] **TEST-10 关键场景矩阵**：功能维度边界场景矩阵（多用户/勿扰/分布式开关等，见 functionality-review.md 第 3 节）中受影响的场景在 `test/systemtest` 或单测有对应用例

### 4. Fuzz 测试（官方安全测试规范要求）

> 官方要求：针对接收并处理用户态参数的模块，必须开发灰白盒 Fuzz 测试套并完成验证。

- [ ] **TEST-11 IPC 入口 Fuzz 覆盖**：新增/修改的 IPC 入口（`AnsManagerStub` 处理函数）在 `test/fuzztest` 有对应 Fuzz 用例；新入口无 Fuzz 覆盖为 P1
- [ ] **TEST-12 反序列化 Fuzz**：新增 Parcelable 字段的 `Unmarshalling` 有 Fuzz 覆盖（恶意报文字段）
- [ ] **TEST-13 Fuzz 发现问题的处理**：Fuzz 崩溃必须修复，不得通过缩小输入域掩盖

### 5. 官方安全测试规范要点（内化）

- [ ] **TEST-14 安全检视问题清零**：安全维度（security-review.md）发现的问题全部修复后才满足安全测试完成标准——本维度在报告中交叉引用安全维度的未修复项
- [ ] **TEST-15 证书密钥检查**：代码中检索 `.cer`/`.pem`/`PRIVATE KEY` 等，确认有效期与加密算法合规（新增证书必须检查）
- [ ] **TEST-16 二进制编译选项**：编译选项符合规范（与 checklist CHK-G01~G03 联动）

---

## 检测方法

```bash
# 变更文件与测试目录映射检查（人工比对）
git diff HEAD --name-only | grep -E "^services/ans/" | sed 's|src/.*|test/|'
# 期望对应 test 目录有同名或相关测试文件变更；无变更则标记 TEST-01 待补

# 新增测试是否挂载 BUILD.gn
NEW_TEST=$(git diff HEAD --name-only --diff-filter=A | grep "test/unittest.*\.cpp$")
for f in $NEW_TEST; do
    dir=$(dirname $f)
    grep -q "$(basename $f)" "$dir/BUILD.gn" || echo "NOT IN BUILD.gn: $f"
done

# HWTEST 使用检查（新测试文件）
grep -L "HWTEST" $(git diff HEAD --name-only --diff-filter=A | grep "test/.*\.cpp$") 2>/dev/null

# Fuzz 入口对照
ls test/fuzztest/   # 与 services/ans IPC 入口清单对照
```

## 严重等级映射

| 类别 | 默认等级 |
|---|---|
| 行为变更完全无测试、Fuzz 崩溃未修复、断言被删除以通过测试 | **P1**（测试维度不设 P0：不直接破坏产品正确性，但门禁建议 conditional） |
| 新 IPC 入口无 Fuzz、错误路径无用例、测试未挂载 BUILD.gn | **P2** |
| 覆盖率欠缺口（<90% 但主体已覆盖）、用例风格问题 | **P2/P3** |
| 建议补齐的场景 | **P3** |

## 输出格式

发现以 `TEST-xxx` 编号输出（见 report-template.md），每条包含：位置（源码 or 测试文件）、问题、缺失的测试场景描述、建议（补什么用例、断言什么）。统计各变更文件的覆盖情况形成映射表。原始产出保存至 `.codecheck/raw/test.md`。
