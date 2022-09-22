/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "reminder_data_manager.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : ReminderDataManagerTest_00200
 * @tc.name      : CheckReminderLimitExceededLocked
 * @tc.desc      : Test CheckReminderLimitExceededLocked function when the  bundleOption is nullptr,return is false
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00200, Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.CheckReminderLimitExceededLocked(bundleOption);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_00300
 * @tc.name      : FindReminderRequestLocked
 * @tc.desc      : Test FindReminderRequestLocked function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00300, Level1)
{
    int32_t reminderId = 1;
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.FindReminderRequestLocked(reminderId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00400
 * @tc.name      : FindReminderRequestLocked
 * @tc.desc      : Test FindReminderRequestLocked function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00400, Level1)
{
    int32_t reminderId = 1;
    std::string pkgName = "PkgName";
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.FindReminderRequestLocked(reminderId, pkgName);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00500
 * @tc.name      : FindNotificationBundleOption
 * @tc.desc      : Test FindNotificationBundleOption function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00500, Level1)
{
    int32_t reminderId = 1;
    ReminderDataManager reminderDataManager;
    sptr<NotificationBundleOption> result = reminderDataManager.FindNotificationBundleOption(reminderId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00700
 * @tc.name      : GetInstance
 * @tc.desc      : Test GetInstance function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00700, Level1)
{
    ReminderDataManager reminderDataManager;
    std::shared_ptr<ReminderDataManager> result = reminderDataManager.GetInstance();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00900
 * @tc.name      : ShouldAlert
 * @tc.desc      : Test ShouldAlert function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_00900, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.ShouldAlert(reminder);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_01200
 * @tc.name      : GetRecentReminderLocked
 * @tc.desc      : Test GetRecentReminderLocked function when the result is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_01200, Level1)
{
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.GetRecentReminderLocked();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_01400
 * @tc.name      : IsAllowedNotify
 * @tc.desc      : Test IsAllowedNotify function when the  reminder is nullptr ,the result is false
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_01400, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.IsAllowedNotify(reminder);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_01500
 * @tc.name      : IsReminderAgentReady
 * @tc.desc      : Test IsReminderAgentReady function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_01500, Level1)
{
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.IsReminderAgentReady();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number    : ReminderDataManagerTest_01700
 * @tc.name      : GetSoundUri
 * @tc.desc      : Test GetSoundUri function when the  reminder is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_01700, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    std::string result = reminderDataManager.GetSoundUri(reminder);
    EXPECT_EQ(result, "//system/etc/Light.ogg");
}

/**
 * @tc.number    : ReminderDataManagerTest_01100
 * @tc.name      : Dump
 * @tc.desc      : Test Dump function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_01100, Level1)
{
    ReminderDataManager reminderDataManager;
    std::string result = reminderDataManager.Dump();
    EXPECT_EQ(result.size(), 68);
}
}  // namespace Notification
}  // namespace OHOS
