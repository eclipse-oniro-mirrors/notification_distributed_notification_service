---
name: unit-test-generator
description: Generate comprehensive unit tests for OpenHarmony Distributed Notification Service that follow project standards include proper assertions use appropriate mocks and achieve 90% branch coverage. Use when adding tests for new code commits files or improving coverage.
---

# Unit Test Generator for Distributed Notification Service

## Overview

Generate comprehensive unit tests for OpenHarmony Distributed Notification Service that follow project standards, include proper assertions, use appropriate mocks, and achieve 90%+ branch coverage.

## Decision Tree

What do you want to test?

├─ New code?
│  ├─ Single file?
│  │  └─ Identify source file → Generate test file manually
│  └─ Multiple files?
│     └─ Identify source files → Generate test files manually
├─ Specific commit?
│  └─ Analyze commit changes → Generate tests for changed files
└─ Improve coverage?
   └─ Generate coverage report → Add tests for uncovered branches

## Core Workflow

### Step 0: Hard Constraint — Test-Only Changes (强制约束：仅修改测试代码)

When writing TDD, you may **ONLY modify test code**. Production code must not be touched:

**Allowed to modify:**
- Test files (`*_test.cpp`) under any `test/` directory
- Test mock files (`mock_*.cpp` / `mock_*.h` under test directories, including `mock/include/`)
- Test `BUILD.gn` (adding test sources, mocks, or test-target-only config)
- Test fixtures/helpers located under test directories

**Forbidden to modify:**
- Production source files (`services/*/src`, `frameworks/*/src`, `interfaces/`, etc.)
- Production headers (`interfaces/inner_api/`, `services/*/include/`, `frameworks/*/include/`, etc.)
- Production `BUILD.gn` / `.gni` files
- IDL files and any generated proxy/stub code

**Rules:**
- If a branch cannot be covered without changing production code, do NOT change it. Report the limitation instead (e.g., "branch X requires a production-code refactor or a mock of dependency Y").
- If existing tests fail due to intentional production-code behavior changes, fix the **tests** (update expectations, fix mock setup, reset mock state pollution) — never the production code.
- Verify before finishing: `git diff --stat` must show changes only under test paths (`test/`, `mock/`).

### Step 1: Identify Test Scope

Determine testing scope based on user request:

**For new code:**
- Identify newly added source files (.cpp, .h)
- Locate corresponding test directory structure
- Check if test file already exists

**For a specific commit:**
- Use `git show --stat <commit>` to identify changed files
- Filter for source files (not test files)
- Focus on modified or added functions

**For a specific file:**
- Read source file to understand class/function structure
- Identify existing test coverage
- Determine untested functions/branches

### Step 2: Analyze Source Code

For each source file to test:

1. **Read source file** to understand:
   - Class structure and inheritance
   - Public/private/protected methods
   - Dependencies and external calls
   - Return types and error handling

2. **Check existing tests** (if any):
   - Read corresponding `*_test.cpp` file
   - Identify already tested functions
   - Note test patterns and naming conventions
   - Check mock usage patterns

3. **Identify test gaps:**
   - Functions without tests
   - Branches not covered (use coverage reports if available)
   - Edge cases not tested (null checks, error paths, boundary conditions)

### Step 3: Determine Mock Requirements

Check dependencies and identify required mocks:

**Common mock types in this project:**
- `mock_bundle_manager.h` - For bundle manager dependencies
- `mock_ipc_skeleton.h` - For IPC skeleton mocking
- `mock_accesstoken_kit.h` - For access token mocking
- `mock_single_kv_store.h` - For key-value store mocking
- `mock_service_registry.h` - For service registry mocking
- `mock_datashare_helper.h` - For data share mocking
- `mock_os_account_manager.h` - For OS account manager mocking

**Mock reference location:** See [MOCK_REFERENCES.md](references/MOCK_REFERENCES.md) for complete mock library details and usage examples.

### Step 4: Generate Test Cases

For each untested function/branch:

1. **Follow naming convention:** `FunctionName_ScenarioNumber` (e.g., `GetSlotType_00001`, `Connect_00001`)

2. **Add test documentation:**
   ```cpp
   /**
    * @tc.name: FunctionName_ScenarioNumber
    * @tc.desc: Description of what test does
    * @tc.type: FUNC
    * @tc.require: issueNumber
    */
   ```

3. **Use appropriate test macro:**
   - `HWTEST_F(ClassName, TestName, Function | SmallTest | Level1)` for most tests
   - Use Level2, Level3, Level4 for slower tests

4. **Include at least one assertion per test:**
   - `EXPECT_EQ()` / `ASSERT_EQ()` for equality
   - `EXPECT_NE()` / `ASSERT_NE()` for inequality
   - `EXPECT_TRUE()` / `ASSERT_TRUE()` for boolean
   - `EXPECT_FALSE()` / `ASSERT_FALSE()` for boolean
   - **Critical:** Every test MUST have at least one assertion

5. **Test all branches:**
   - Success paths
   - Error paths (null checks, invalid inputs)
   - Boundary conditions (empty strings, zero values, max values)
   - Exception/error code handling

### Step 5: Update BUILD.gn

Add new test file to appropriate BUILD.gn:

1. **Locate BUILD.gn** in test directory
2. **Add test source** to `sources` array
3. **Ensure dependencies** are correct in `deps` and `external_deps`
4. **Verify include_dirs** contain necessary paths

See [BUILD_CONFIG.md](references/BUILD_CONFIG.md) for BUILD.gn configuration templates.

### Step 6: Post-Generation Checks (新增 TDD 后必检)

**Scope:** These checks apply ONLY to **newly added tests**. Never modify or delete existing test items because of these checks.

After generating each new test (TDD), run the following mandatory checks on the new tests:

1. **Non-tautological assertion:** Every new test MUST contain at least one assertion that can actually fail (non-永真断言).
   - Valid: `EXPECT_EQ(result, expectedValue)`, `EXPECT_NE(ptr, nullptr)`, `EXPECT_FALSE(result)`
   - Invalid (永真): `EXPECT_EQ(1, 1)`, `EXPECT_TRUE(true)`, `EXPECT_NE(nullptr, nullptr)`
   - If a new test contains only tautological assertions, rewrite it with a real verifiable assertion; if none is possible, do not add the test.

2. **Minimum test body length:** Every new test body must be **at least 3 lines**. If fewer than 3 lines, do not add the test.

3. **Line length limit:** Every line of the new tests must be **at most 120 characters**. If a line exceeds 120 characters, wrap it, placing the operator at the **end** of the line:
   ```cpp
   EXPECT_EQ(bundleManagerHelper.GetDistributedNotificationEnabled(bundleName, userId),
       false);
   ```

4. **Preserve existing tests:** Do NOT delete or rewrite existing test items, even if they violate checks 1–3. These checks govern only newly generated tests; existing tests may only be changed when explicitly requested (e.g., fixing a broken expectation caused by intentional production-code behavior change).

### Step 7: Build and Verify

1. **Build test:**
   ```bash
   ./build.sh --product-name rk3568 --build-target <test_target>
   ```

2. **Run test** to verify it compiles and executes

3. **Check coverage** (if coverage tools available):
   - Generate coverage report
   - Verify branch coverage meets 90% requirement
   - Add more tests if coverage is insufficient

## Test Structure Template

```cpp
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#define private public
#define protected public

#include "class_under_test.h"

#include "mock_dependency.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class ClassNameTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: MethodName_00001
 * @tc.desc: Test MethodName with valid input
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ClassNameTest, MethodName_00001, Function | SmallTest | Level1)
{
    // Arrange
    ClassName className;
    
    // Act
    auto result = className.MethodName(validInput);
    
    // Assert
    EXPECT_EQ(result, expectedValue);
}

}  // namespace Notification
}  // namespace OHOS
```

## Coverage Requirements

**Target:** 90%+ branch coverage for all tested code

**Verification:**
1. Use coverage tools (gcov/lcov if available)
2. Identify uncovered branches
3. Add tests for each uncovered branch
4. Re-verify coverage meets 90% threshold

**Common coverage gaps to address:**
- Null/empty input validation
- Error code paths
- Conditional branches (if/else statements)
- Loop conditions
- Exception handling paths

## Quality Checks

Before completing test generation, verify:

- [ ] `git diff --stat` shows changes only under test paths (test files, mocks, test BUILD.gn) — no production code touched (Step 0)
- [ ] Every test has at least one assertion (EXPECT/ASSERT)
- [ ] Every new test has at least one non-tautological assertion (can actually fail)
- [ ] Every new test body is at least 3 lines (do not add if fewer)
- [ ] Every line of the new tests is at most 120 characters; wrapped lines place operators at end of line
- [ ] No existing test items deleted or rewritten (Step 6.4)
- [ ] All tests follow naming convention: `FunctionName_ScenarioNumber`
- [ ] Test documentation includes @tc.name, @tc.desc, @tc.type, @tc.require
- [ ] Appropriate use_exceptions in BUILD.gn if using EXPECT_THROW/EXPECT_NO_THROW
- [ ] Appropriate mocks are included and used correctly
- [ ] BUILD.gn is updated with new test source
- [ ] Test compiles without errors
- [ ] Test executes successfully
- [ ] Branch coverage meets 90% requirement

## Troubleshooting

**Issue:** Build fails with "undefined reference"
**Solution:** Check include paths and dependencies in BUILD.gn. See [BUILD_CONFIG.md](references/BUILD_CONFIG.md)

**Issue:** Coverage below 90%
**Solution:** Generate coverage report and add tests for uncovered branches

**Issue:** Mock not found
**Solution:** Check [MOCK_REFERENCES.md](references/MOCK_REFERENCES.md) for available mocks or create new mock using [MOCK_CREATION_GUIDE.md](references/MOCK_CREATION_GUIDE.md)

**Issue:** Exception tests fail
**Solution:** Ensure `use_exceptions = true` is added to BUILD.gn. See [BUILD_CONFIG.md](references/BUILD_CONFIG.md)

## References


- **[TEST_PATTERNS.md](references/TEST_PATTERNS.md)** - 10 essential test patterns
- **[MOCK_REFERENCES.md](references/MOCK_REFERENCES.md)** - 5 common mock libraries
- **[MOCK_CREATION_GUIDE.md](references/MOCK_CREATION_GUIDE.md)** - Mock creation guide
- **[BUILD_CONFIG.md](references/BUILD_CONFIG.md)** - BUILD.gn configuration reference
