/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>
#include "reminder_service_ability.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class ReminderServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : ReminderServiceAbilityTest_00100
 * @tc.name      : ReminderServiceAbility_0100
 * @tc.desc      : Structure ReminderServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderServiceAbilityTest, ReminderServiceAbilityTest_00100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderServiceAbility(systemAbilityId, runOnCreate);
}

/**
 * @tc.number    : ReminderServiceAbilityTest_00200
 * @tc.name      : ReminderServiceAbility_0200
 * @tc.desc      : Structure ReminderServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderServiceAbilityTest, ReminderServiceAbilityTest_00200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
}

/**
 * @tc.number    : ReminderServiceAbilityTest_00300
 * @tc.name      : ReminderServiceAbility_0300
 * @tc.desc      : Structure ReminderServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderServiceAbilityTest, ReminderServiceAbilityTest_00300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStop();
    test.OnStart();
}
}  // namespace Notification
}  // namespace OHOS
