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

#include "gtest/gtest.h"
#include "reminder_agent_service_ability.h"

using namespace testing::ext;

namespace OHOS::Notification {
class ReminderAgentServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_001
 * @tc.name      : ReminderAgentServiceAbilityTest_001
 * @tc.desc      : Structure ReminderAgentServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_001, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility(systemAbilityId, runOnCreate);
}

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_002
 * @tc.name      : ReminderAgentServiceAbilityTest_002
 * @tc.desc      : OnStart
 */
HWTEST_F(ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_002, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
    test.OnStart();
    EXPECT_NE(test.service_, nullptr);
}

/**
 * @tc.number    : ReminderAgentServiceAbilityTest_003
 * @tc.name      : ReminderAgentServiceAbility_0300
 * @tc.desc      : OnStop
 */
HWTEST_F(ReminderAgentServiceAbilityTest, ReminderAgentServiceAbilityTest_00300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    ReminderAgentServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
    test.OnStop();
    EXPECT_EQ(test.service_, nullptr);
}
}  // namespace OHOS::Notification
