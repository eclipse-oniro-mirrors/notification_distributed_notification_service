/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "errors.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#include "reminder_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "reminder_ut_constant.h"
#include "iremote_object.h"
#include "accesstoken_kit.h"
#include "mock_ipc_skeleton.h"
#include "mock_accesstoken_kit.h"

extern void MockIsOsAccountExists(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {

class ReminderServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddLiveViewSlot(bool isForceControl);
    void MockSystemApp();

private:
    static sptr<ReminderService> ReminderService_;
};

sptr<ReminderService> ReminderServiceTest::ReminderService_ = nullptr;

void ReminderServiceTest::SetUpTestCase()
{
    MockIsOsAccountExists(true);
}

void ReminderServiceTest::TearDownTestCase() {}

void ReminderServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    ReminderService_ = new (std::nothrow) ReminderService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    ReminderService_->CancelAllReminders();
    MockAccesstokenKit::MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void ReminderServiceTest::TearDown()
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    ReminderService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

void ReminderServiceTest::MockSystemApp()
{
    MockAccesstokenKit::MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockAccesstokenKit::MockIsSystemApp(true);
    MockAccesstokenKit::MockIsVerfyPermisson(true);
}

inline void SleepForFC()
{
    // For Reminder Flow Control
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.number    : ReminderServiceTest_13500
 * @tc.name      : Reminder_GetValidReminders_0100
 * @tc.desc      : Test GetValidReminders function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServiceTest, ReminderServiceTest_13500, Function | SmallTest | Level1)
{
    std::vector<ReminderRequestAdaptation> reminders;
    ASSERT_EQ(ReminderService_->GetValidReminders(reminders), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : ReminderServiceTest_16900
 * @tc.name      : Reminder_GetActiveNotifications_0100
 * @tc.desc      : Test function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(ReminderServiceTest, ReminderServiceTest_16900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "Reminder_GetActiveNotifications_0100 test start";

    MockAccesstokenKit::MockIsNonBundleName(true);
    MockSystemApp();
    int32_t reminderId = 1;
    ASSERT_EQ(ReminderService_->CancelReminder(reminderId), ERR_NO_INIT);

    ASSERT_EQ(ReminderService_->CancelAllReminders(), ERR_NO_INIT);

    std::vector<ReminderRequestAdaptation> reminders;
    ASSERT_EQ(ReminderService_->GetValidReminders(reminders), ERR_NO_INIT);

    MockAccesstokenKit::MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "Reminder_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AddExcludeDate_00001
 * @tc.name      : Test AddExcludeDate
 * @tc.desc      : Test AddExcludeDate function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServiceTest, AddExcludeDate_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    uint64_t time = 124325;
    MockAccesstokenKit::MockIsVerfyPermisson(false);
    ASSERT_EQ(ReminderService_->AddExcludeDate(reminderId, time), (int)ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerfyPermisson(true);
    MockAccesstokenKit::MockIsNonBundleName(false);
    ASSERT_EQ(ReminderService_->AddExcludeDate(reminderId, time), (int)ERR_NO_INIT);
    MockAccesstokenKit::MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : DelExcludeDates_00002
 * @tc.name      : Test DelExcludeDates
 * @tc.desc      : Test DelExcludeDates function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServiceTest, DelExcludeDates_00002, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    MockAccesstokenKit::MockIsVerfyPermisson(false);
    ASSERT_EQ(ReminderService_->DelExcludeDates(reminderId), (int)ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerfyPermisson(true);
    MockAccesstokenKit::MockIsNonBundleName(false);
    ASSERT_EQ(ReminderService_->DelExcludeDates(reminderId), (int)ERR_NO_INIT);
    MockAccesstokenKit::MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : GetExcludeDates_00001
 * @tc.name      : Test GetExcludeDates
 * @tc.desc      : Test GetExcludeDates function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServiceTest, GetExcludeDates_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    std::vector<int64_t> times;
    MockAccesstokenKit::MockIsVerfyPermisson(false);
    ASSERT_EQ(ReminderService_->GetExcludeDates(reminderId, times), (int)ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerfyPermisson(true);
    MockAccesstokenKit::MockIsNonBundleName(false);
    ASSERT_EQ(ReminderService_->GetExcludeDates(reminderId, times), (int)ERR_NO_INIT);
    MockAccesstokenKit::MockIsVerfyPermisson(false);
}
}  // namespace Notification
}  // namespace OHOS
