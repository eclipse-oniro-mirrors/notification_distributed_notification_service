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
#include "reminder_agent_service_ability.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class ReminderAgentServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_00100
 * @tc.name      : ReminderAgentServiceAbility_0100
 * @tc.desc      : Structure ReminderAgentServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_00100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility(systemAbilityId, runOnCreate);
}

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_00200
 * @tc.name      : ReminderAgentServiceAbility_0200
 * @tc.desc      : Structure ReminderAgentServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_00200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
    test.OnStart();
}

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_00300
 * @tc.name      : ReminderAgentServiceAbility_0300
 * @tc.desc      : Structure ReminderAgentServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_00300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStop();
    test.OnStart();
}
}  // namespace Notification
}  // namespace OHOS
