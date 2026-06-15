/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "reminder_data_manager.h"

#include "mock_reminder_datashare_helper.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;
namespace OHOS::Notification {
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderDataManager::InitInstance();
        manager = ReminderDataManager::GetInstance();
    }
    static void TearDownTestCase()
    {
        manager = nullptr;
    }
    void SetUp() {};
    void TearDown() {};

public:
    static std::shared_ptr<ReminderDataManager> manager;
};

std::shared_ptr<ReminderDataManager> ReminderDataManagerTest::manager = nullptr;

/**
 * @tc.name: IsInDoNotDisturbMode_001
 * @tc.desc: Test IsInDoNotDisturbMode
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, IsInDoNotDisturbMode_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::MockQuery(false, "", reminders);
    bool ret = manager->IsInDoNotDisturbMode(100);
    EXPECT_EQ(ret, true);
    MockReminderDatashareHelper::MockQuery(true, "1", reminders);
    ret = manager->IsInDoNotDisturbMode(100);
    EXPECT_EQ(ret, true);
    MockReminderDatashareHelper::MockQuery(true, "0", reminders);
    ret = manager->IsInDoNotDisturbMode(100);
    EXPECT_EQ(ret, false);
#endif
}

/**
 * @tc.name: CheckSoundConfig_001
 * @tc.desc: Test CheckSoundConfig
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, CheckSoundConfig_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    int32_t flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    bool ret = manager->CheckSoundConfig(true, flag, 0);
    EXPECT_EQ(ret, false);
    ret = manager->CheckSoundConfig(false, flag, 0);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    ret = manager->CheckSoundConfig(false, flag, 0);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    ret = manager->CheckSoundConfig(false, flag, 0);
    EXPECT_EQ(ret, false);
    ret = manager->CheckSoundConfig(false, flag, 1);
    EXPECT_EQ(ret, true);
#endif
}

/**
 * @tc.name: GetSettingsData_001
 * @tc.desc: Test GetSettingsData
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, GetSettingsData_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::MockQuery(false, "", reminders);
    bool ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::MockQuery(true, "0", reminders);
    ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::MockQuery(true, "1", reminders);
    ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, true);
#endif
}

/**
 * @tc.name: CheckVibrationConfig_001
 * @tc.desc: Test CheckVibrationConfig
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, CheckVibrationConfig_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    int32_t flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    bool ret = manager->CheckVibrationConfig(100, true, flag, 0);
    EXPECT_EQ(ret, false);
    ret = manager->CheckVibrationConfig(100, false, flag, 0);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    ret = manager->CheckVibrationConfig(100, false, flag, 0);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::MockQuery(true, "0", reminders);
    ret = manager->CheckVibrationConfig(100, false, flag, 0);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::MockQuery(true, "1", reminders);
    auto client = std::move(manager->systemSoundClient_);
    ret = manager->CheckVibrationConfig(100, false, flag, 0);
    EXPECT_EQ(ret, false);
    manager->systemSoundClient_ = std::move(client);
#endif
}
}  // namespace OHOS::Notification
