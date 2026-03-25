# AGENTS.md - Agent Coding Guidelines for Distributed Notification Service

## Overview

This is the OpenHarmony Notification Subsystem (ANS). The codebase is primarily C++ with some JavaScript/ETS components.

## Project Structure

```
distributed_notification_service/
├── interfaces/          # Public APIs (inner_api, kits, ndk)
├── frameworks/          # Framework implementations (ans, core, extension, reminder, ets)
├── services/            # Service implementations (ans, distributed, reminder)
├── test/                # Test resources and mocks
└── tools/               # Development tools
```

## Build Commands

### Build Current Project

This is an OpenHarmony subsystem built with GN (Generate Ninja). Build from the OpenHarmony root:

```bash
# Build entire notification subsystem
./build.sh --product-name rk3568 --build-target distributed_notification_service
```

### Build Current Project Tests

Tests are located in `test/unittest/` directories and use GoogleTest. Build and run tests:

```bash
# Build all unit tests
./build.sh --product-name rk3568 --build-target distributed_notification_service_test
```

### Test Naming Convention

Test files follow pattern: `*_test.cpp`
Test cases use HWTEST_F macro:
```cpp
HWTEST_F(ClassName, TestName, Level1)
```

## Code Style Guidelines

### Line Length

Maximum line width is 120 characters.

### File Headers

Every source file must include the Apache 2.0 license header:

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
```

### Include Order

1. Corresponding header (for .cpp files)
2. Module headers
3. OpenHarmony internal headers
4. Third-party headers
5. Standard library headers

```cpp
#include "notification_slot_filter.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "notification_preferences.h"

#include <string>
#include <vector>
```

### Namespace

All code lives in `OHOS::Notification` namespace:

```cpp
namespace OHOS {
namespace Notification {

class NotificationSlot : public Parcelable {
public:
    // ...
};

}  // namespace Notification
}  // namespace OHOS
```

### Naming Conventions

- **Classes**: PascalCase (e.g., `NotificationSlot`, `NotificationRequest`)
- **Methods**: PascalCase (e.g., `GetSlotType()`, `SetEnableLight()`)
- **Variables**: camelCase (e.g., `notificationSlot`, `record`)
- **Constants**: UPPER_SNAKE_CASE for macros, PascalCase for enums
- **Files**: snake_case (e.g., `notification_slot.h`, `notification_slot.cpp`)

### Types and Smart Pointers

- Use `sptr` for shared pointers (from OpenHarmony):

```cpp
#include "refbase.h"

sptr<NotificationSlot> notificationSlot = new NotificationSlot();
sptr<NotificationSlot> slot = notificationSlot->Unmarshalling(parcel);
```

- Use standard types from `std::` for containers:

```cpp
#include <string>
#include <vector>
#include <map>
#include <set>

std::string GetId() const;
std::vector<std::string> GetIds() const;
```
- Use `int32_t`, `uint32_t`, `int64_t`, `uint64_t` for integer types with specific sizes
- Use `ErrCode` for error return values (defined in the codebase)
- Use `bool` for boolean values
- Use `std::string` for strings
- Use `std::vector<>` for dynamic arrays
- Use `constexpr` for compile-time constants
- Use `override` keyword for overridden virtual methods

### Logging

Use the ANS_LOG* macros from `ans_log_wrapper.h`:

```cpp
#include "ans_log_wrapper.h"

ANS_LOGD("Debug info: %{public}s", info.c_str());   // Debug
ANS_LOGI("Important: %{public}d", value);              // Info
ANS_LOGW("Warning: %{public}s", warning.c_str());    // Warning
ANS_LOGE("Error: %{public}d", errorCode);            // Error
```

- Use `%{public}s` / `%{public}d` for format specifiers to ensure visibility
- Log at appropriate level (D < I < W < E)

### Error Handling

Return `AnsStatus` for operation results:

```cpp
#include "ans_inner_errors.h"

AnsStatus OnPublish(const std::shared_ptr<NotificationRecord>& record)
{
    if (record->slot != nullptr) {
        // Process...
        return AnsStatus();
    } else {
        ANS_LOGE("Non valid slot!");
        return AnsStatus(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST, "Non valid slot!");
    }
}
```

Common error codes are defined in `ans_inner_errors.h`.

### Parcelable/IPC

For objects that can be marshalled/unmarshalled for IPC:

```cpp
#include "parcel.h"

class NotificationSlot : public Parcelable {
public:
    virtual bool Marshalling(Parcel& parcel) const override;
    virtual bool Unmarshalling(Parcel& parcel) override;
};
```

### Testing Guidelines

- Use `HWTEST_F(ClassName, TestName, Function | SmallTest | Level1)` macro for test cases
- Test naming: `FunctionName_ScenarioNumber` (e.g., `GetBundleName_00001`)
- Add test documentation comments:
  ```cpp
  /**
   * @tc.name: TestName
   * @tc.desc: Description of what the test does
   * @tc.type: FUNC
   * @tc.require: issueNumber
   */
  ```
- Use `#define private public` and `#define protected public` to test private members
- Use `EXPECT_EQ`, `EXPECT_NE`, `ASSERT_EQ`, etc. for assertions
- Create test fixtures with `SetUpTestCase()`, `TearDownTestCase()`, `SetUp()`, `TearDown()`

Follow existing test patterns:

```cpp
#include <gtest/gtest.h>

#define private public  // Only when testing private members

using namespace testing::ext;

class NotificationSlotTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(NotificationSlotTest, GetSlotTypeByString_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType type;
    EXPECT_EQ(NotificationSlot::GetSlotTypeByString(NotificationSlot::CONTENT_INFORMATION, type), true);
    EXPECT_EQ(type, NotificationConstant::SlotType::CONTENT_INFORMATION);
}
```

Test levels: Level1 (fast), Level2, Level3, Level4 (slow)

### Conditional Compilation

Use feature flags defined in `notification.gni`:

```cpp
#if defined(ANS_FEATURE_ORIGINAL_DISTRIBUTED)
    // Distributed notification code
#endif

#if defined(ALL_SCENARIO_COLLABORATION)
    // Scenario collaboration code
#endif
```

### Documentation

Use Doxygen-style comments for public APIs:

```cpp
/**
 * @brief Obtains the ID of a NotificationSlot object.
 *
 * @return Returns the ID of the NotificationSlot object,
 *         which is set by NotificationSlot(string, string, NotificationLevel).
 */
std::string GetId() const;
```

### GN Build Files
- Use `import()` for including other .gni files
- Use `ohos_unittest()`, `ohos_shared_library()`, `ohos_source_set()` templates
- Add `external_deps` for dependencies on other OpenHarmony components
- Add `deps` for internal dependencies
- Use `sanitize` section for security hardening options

## Key Dependencies

- `hilog`: Logging
- `ipc_core`: IPC communication
- `safwk`: System ability framework
- `bundle_framework`: Bundle management
- `ability_runtime`: Ability runtime
- `eventhandler`: Event handling
- `ffrt`: Fast Forward Runtime for async tasks

## Common Tasks

### Adding a New Test

1. Create test file in appropriate `test/unittest/` directory
2. Add test source to the relevant `BUILD.gn` `ohos_unittest` target
3. Build with: `./build.sh --product-name <product> --build-target <test_target>`

### Adding a New Source File

1. Add to appropriate `sources` list in the relevant `BUILD.gn`
2. Add dependencies in `deps` or `external_deps`
3. Ensure proper include paths are configured

### Modifying Public APIs

Public APIs are in `interfaces/` directory. Changes may require:
1. Updating the NAPI bindings in `interfaces/kits/napi/`
2. Updating inner APIs in `interfaces/inner_api/`
3. Updating the version script (*.map file) if adding new symbols

## Commit Messages

Follow the OpenHarmony commit message format. End your commit message with:

```
Co-Authored-By: Agent
```

Example:
```
Add TDD test cases for notification slot filtering

Co-Authored-By: Agent
```

When committing, use the `--signoff` flag:
```bash
git commit --signoff -m "Your commit message

Co-Authored-By: Agent"
```