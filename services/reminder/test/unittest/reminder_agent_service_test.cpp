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

#include "gtest/gtest.h"
#include "reminder_agent_service.h"

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "reminder_request.h"
#include "reminder_data_manager.h"
#include "reminder_request_alarm.h"
#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"

#include "mock_accesstoken_kit.h"
#include "mock_os_account_manager.h"
#include "mock_notification_helper.h"
#include "mock_reminder_data_manager.h"
#include "mock_reminder_bundle_manager_helper.h"

#include <chrono>
#include <thread>

using namespace testing::ext;

namespace OHOS::Notification {
class ReminderAgentServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {}
    void TearDown() {}

private:
    static sptr<ReminderAgentService> reminderAgentService_;
};

sptr<ReminderAgentService> ReminderAgentServiceTest::reminderAgentService_ = nullptr;

void ReminderAgentServiceTest::SetUpTestCase()
{
    reminderAgentService_ = new (std::nothrow) ReminderAgentService();
}

void ReminderAgentServiceTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
    reminderAgentService_ = nullptr;
}

/**
 * @tc.name: ReminderAgentServiceTest_001
 * @tc.desc: Test GetInstance function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_001, Function | SmallTest | Level1)
{
    EXPECT_NE(ReminderAgentService::GetInstance(), nullptr);
    EXPECT_NE(ReminderAgentService::GetInstance(), nullptr);
}

/**
 * @tc.name: ReminderAgentServiceTest_002
 * @tc.desc: Test PublishReminder function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_002, Function | SmallTest | Level1)
{
    // test CreateReminderRequest
    int32_t reminderId = 0;
    ReminderRequest reminder;
    EXPECT_EQ(reminderAgentService_->PublishReminder(reminder, reminderId), ERR_REMINDER_INVALID_PARAM);
    
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    ReminderRequestAlarm alarm;
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test AllowUseReminder
    MockNotificationHelper::MockIsAllowUseReminder(false);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_REMINDER_NUMBER_OVERLOAD);
    MockNotificationHelper::MockIsAllowUseReminder(true);

    // test InitReminderRequest
    auto wantInfo = alarm.GetMaxScreenWantAgentInfo();
    alarm.SetMaxScreenWantAgentInfo(nullptr);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_REMINDER_INVALID_PARAM);
    alarm.SetMaxScreenWantAgentInfo(wantInfo);

    // test IsSystemApp and IsAllowedNotify
    alarm.SetSystemApp(false);
    MockNotificationHelper::MockIsAllowedNotify(false, 1);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_REMINDER_NOTIFICATION_NOT_ENABLE);
    MockNotificationHelper::MockIsAllowedNotify(false, 0);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_REMINDER_NOTIFICATION_NOT_ENABLE);
    MockNotificationHelper::MockIsAllowedNotify(true, 0);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_NO_INIT);
    alarm.SetSystemApp(true);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::PublishReminder
    MockReminderDataManager::MockPublishReminder(1);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), 1);
    MockReminderDataManager::MockPublishReminder(0);
    EXPECT_EQ(reminderAgentService_->PublishReminder(alarm, reminderId), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_003
 * @tc.desc: Test CancelReminder function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_003, Function | SmallTest | Level1)
{
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->CancelReminder(0), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->CancelReminder(0), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::CancelReminder
    MockReminderDataManager::MockCancelReminder(1);
    EXPECT_EQ(reminderAgentService_->CancelReminder(0), 1);
    MockReminderDataManager::MockCancelReminder(0);
    EXPECT_EQ(reminderAgentService_->CancelReminder(0), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_004
 * @tc.desc: Test CancelAllReminders function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_004, Function | SmallTest | Level1)
{
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->CancelAllReminders(), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->CancelAllReminders(), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::CancelAllReminders
    MockReminderDataManager::MockCancelAllReminders(1);
    EXPECT_EQ(reminderAgentService_->CancelAllReminders(), 1);
    MockReminderDataManager::MockCancelAllReminders(0);
    EXPECT_EQ(reminderAgentService_->CancelAllReminders(), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_005
 * @tc.desc: Test GetValidReminders function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_005, Function | SmallTest | Level1)
{
    // test CheckReminderPermission
    std::vector<ReminderRequestAdaptation> reminders;
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->GetValidReminders(reminders), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->GetValidReminders(reminders), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::GetValidReminders
    EXPECT_EQ(reminderAgentService_->GetValidReminders(reminders), ERR_OK);
}

/**
 * @tc.name: ReminderAgentServiceTest_006
 * @tc.desc: Test AddExcludeDate function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_006, Function | SmallTest | Level1)
{
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->AddExcludeDate(0, 0), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->AddExcludeDate(0, 0), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::AddExcludeDate
    MockReminderDataManager::MockAddExcludeDate(1);
    EXPECT_EQ(reminderAgentService_->AddExcludeDate(0, 0), 1);
    MockReminderDataManager::MockAddExcludeDate(0);
    EXPECT_EQ(reminderAgentService_->AddExcludeDate(0, 0), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_007
 * @tc.desc: Test DelExcludeDates function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_007, Function | SmallTest | Level1)
{
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->DelExcludeDates(0), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->DelExcludeDates(0), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::DelExcludeDates
    MockReminderDataManager::MockDelExcludeDates(1);
    EXPECT_EQ(reminderAgentService_->DelExcludeDates(0), 1);
    MockReminderDataManager::MockDelExcludeDates(0);
    EXPECT_EQ(reminderAgentService_->DelExcludeDates(0), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_008
 * @tc.desc: Test GetExcludeDates function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_008, Function | SmallTest | Level1)
{
    std::vector<int64_t> dates;
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->GetExcludeDates(0, dates), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->GetExcludeDates(0, dates), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::GetExcludeDates
    MockReminderDataManager::MockGetExcludeDates(1);
    EXPECT_EQ(reminderAgentService_->GetExcludeDates(0, dates), 1);
    MockReminderDataManager::MockGetExcludeDates(0);
    EXPECT_EQ(reminderAgentService_->GetExcludeDates(0, dates), 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_009
 * @tc.desc: Test TryPostDelayUnloadTask function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_009, Function | SmallTest | Level1)
{
    reminderAgentService_->TryPostDelayUnloadTask(1000);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_NE(reminderAgentService_->tryUnloadTask_, nullptr);
    reminderAgentService_->TryPostDelayUnloadTask(1000*1000);
    EXPECT_NE(reminderAgentService_->tryUnloadTask_, nullptr);
}

/**
 * @tc.name: ReminderAgentServiceTest_010
 * @tc.desc: Test TryUnloadService function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_010, Function | SmallTest | Level1)
{
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    reminderAgentService_->TryUnloadService();
    EXPECT_EQ(reminderAgentService_->tryUnloadTask_, nullptr);
    ReminderDataManager::InitInstance();

    MockReminderDataManager::MockQueryActiveReminderCount(1);
    reminderAgentService_->TryUnloadService();
    EXPECT_EQ(reminderAgentService_->tryUnloadTask_, nullptr);
    MockReminderDataManager::MockQueryActiveReminderCount(0);
    
    reminderAgentService_->TryUnloadService();
    EXPECT_EQ(reminderAgentService_->tryUnloadTask_, nullptr);
}

/**
 * @tc.name: ReminderAgentServiceTest_011
 * @tc.desc: Test ChangeReminderAgentLoadConfig function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_011, Function | SmallTest | Level1)
{
    reminderAgentService_->ChangeReminderAgentLoadConfig(1);
    EXPECT_EQ(reminderAgentService_->reminderAgentState_, 1);

    reminderAgentService_->ChangeReminderAgentLoadConfig(0);
    EXPECT_EQ(reminderAgentService_->reminderAgentState_, 0);
}

/**
 * @tc.name: ReminderAgentServiceTest_012
 * @tc.desc: Test CreateReminderRequest function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_012, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer;
    auto reminder = reminderAgentService_->CreateReminderRequest(timer);
    EXPECT_EQ(reminder->GetReminderType(), ReminderRequest::ReminderType::TIMER);

    ReminderRequestAlarm alarm;
    reminder = reminderAgentService_->CreateReminderRequest(alarm);
    EXPECT_EQ(reminder->GetReminderType(), ReminderRequest::ReminderType::ALARM);

    ReminderRequestCalendar calendar;
    reminder = reminderAgentService_->CreateReminderRequest(calendar);
    EXPECT_EQ(reminder->GetReminderType(), ReminderRequest::ReminderType::CALENDAR);

    ReminderRequest request;
    reminder = reminderAgentService_->CreateReminderRequest(request);
    EXPECT_EQ(reminder, nullptr);
}

/**
 * @tc.name: ReminderAgentServiceTest_013
 * @tc.desc: Test InitReminderRequest function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_013, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = new (std::nothrow) ReminderRequestCalendar();
    auto wantInfo = reminder->wantAgentInfo_;
    reminder->wantAgentInfo_ = nullptr;
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);
    reminder->wantAgentInfo_ = wantInfo;

    auto maxWantInfo = reminder->maxScreenWantAgentInfo_;
    reminder->maxScreenWantAgentInfo_ = nullptr;
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);
    reminder->maxScreenWantAgentInfo_ = maxWantInfo;

    reminder->wantAgentInfo_->pkgName = "want";
    reminder->maxScreenWantAgentInfo_->pkgName = "maxWant";
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);

    reminder->maxScreenWantAgentInfo_->pkgName = "";
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);

    reminder->wantAgentInfo_->pkgName = "";
    reminder->maxScreenWantAgentInfo_->pkgName = "maxWant";
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);

    MockOsAccountManager::MockGetForegroundOsAccountLocalId(1);
    reminder->maxScreenWantAgentInfo_->pkgName = "test";
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);
    reminder->SetSystemApp(true);
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_REMINDER_INVALID_PARAM);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(0);
    
    EXPECT_EQ(reminderAgentService_->InitReminderRequest(reminder, "test", 0), ERR_OK);
}

/**
 * @tc.name: ReminderAgentServiceTest_014
 * @tc.desc: Test CheckReminderPermission function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_014, Function | SmallTest | Level1)
{
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    EXPECT_EQ(reminderAgentService_->CheckReminderPermission(), false);
    MockAccesstokenKit::MockIsVerifyPermisson(true);
    EXPECT_EQ(reminderAgentService_->CheckReminderPermission(), true);
}

/**
 * @tc.name: ReminderAgentServiceTest_015
 * @tc.desc: Test IsSystemApp function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_015, Function | SmallTest | Level1)
{
    int32_t flag = static_cast<int32_t>(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    flag = ~flag;
    MockAccesstokenKit::MockGetTokenTypeFlag(flag);
    EXPECT_EQ(reminderAgentService_->IsSystemApp(), false);
    flag = ~flag;
    MockAccesstokenKit::MockGetTokenTypeFlag(flag);
    MockAccesstokenKit::MockIsSystemApp(false);
    EXPECT_EQ(reminderAgentService_->IsSystemApp(), false);
    MockAccesstokenKit::MockIsSystemApp(true);
    EXPECT_EQ(reminderAgentService_->IsSystemApp(), true);
}

/**
 * @tc.name: ReminderAgentServiceTest_016
 * @tc.desc: Test UpdateReminder function
 * @tc.type: FUNC
 * @tc.require: issueI5S4VP
 */
HWTEST_F(ReminderAgentServiceTest, ReminderAgentServiceTest_016, Function | SmallTest | Level1)
{
    // test CreateReminderRequest
    int32_t reminderId = 0;
    ReminderRequest reminder;
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, reminder), ERR_REMINDER_INVALID_PARAM);
    
    // test CheckReminderPermission
    MockAccesstokenKit::MockIsVerifyPermisson(false);
    ReminderRequestAlarm alarm;
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), ERR_REMINDER_PERMISSION_DENIED);
    MockAccesstokenKit::MockIsVerifyPermisson(true);

    // test InitReminderRequest
    auto wantInfo = alarm.GetMaxScreenWantAgentInfo();
    alarm.SetMaxScreenWantAgentInfo(nullptr);
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), ERR_REMINDER_INVALID_PARAM);
    alarm.SetMaxScreenWantAgentInfo(wantInfo);

    // test ReminderDataManager::GetInstance()
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), ERR_NO_INIT);
    alarm.SetSystemApp(true);
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), ERR_NO_INIT);
    ReminderDataManager::InitInstance();

    // test ReminderDataManager::UpdateReminder
    MockReminderDataManager::MockUpdateReminder(1);
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), 1);
    MockReminderDataManager::MockUpdateReminder(0);
    EXPECT_EQ(reminderAgentService_->UpdateReminder(reminderId, alarm), 0);
}
}  // namespace OHOS::Notification
