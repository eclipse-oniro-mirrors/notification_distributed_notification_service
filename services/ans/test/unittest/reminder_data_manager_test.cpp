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
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "reminder_data_manager.h"
#include "reminder_event_manager.h"
#include "reminder_request_timer.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::EventFwk;
namespace OHOS {
namespace Notification {
static auto manager = std::make_shared<ReminderDataManager>();
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: ReminderDataManagerTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    manager->PublishReminder(reminder, option);
    manager->CancelReminder(-1, option);
    manager->CancelAllReminders("", -1);
    manager->CancelAllReminders(-1);
    manager->IsMatched(reminder, "", -1);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_002
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_002, Level1)
{
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    std::vector<sptr<ReminderRequest>> vec;
    manager->GetValidReminders(option, vec);
    manager->CheckReminderLimitExceededLocked(option);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->CancelNotification(reminder);
    reminder->SetReminderId(10);
    manager->AddToShowedReminders(reminder);
    manager->AddToShowedReminders(reminder);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_003
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_003, Level1)
{
    manager->isReminderAgentReady_ = false;
    manager->alertingReminderId_ = -1;
    manager->OnUserSwitch(0);
    manager->OnUserRemove(0);
    manager->alertingReminderId_ = 1;
    manager->OnUserSwitch(0);
    manager->isReminderAgentReady_ = true;
    manager->OnUserSwitch(0);
    manager->alertingReminderId_ = -1;
    manager->OnUserSwitch(0);
    manager->OnUserRemove(0);
    manager->OnServiceStart();
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_004
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_004, Level1)
{
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    manager->OnProcessDiedLocked(option);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->CreateTimerInfo(ReminderDataManager::TimerType::TRIGGER_TIMER, reminder);
    manager->CreateTimerInfo(ReminderDataManager::TimerType::ALERTING_TIMER, reminder);
    manager->FindReminderRequestLocked(0, "");
    reminder->SetReminderId(10);
    manager->reminderVector_.push_back(reminder);
    manager->FindReminderRequestLocked(10, "");
    option->SetBundleName("test");
    manager->notificationBundleOptionMap_[10] = option;
    manager->FindReminderRequestLocked(10, "");
    manager->FindReminderRequestLocked(10, "test");
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_005
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_005, Level1)
{
    EventFwk::Want want;
    manager->CloseReminder(want, true);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->SetReminderId(1);
    manager->activeReminderId_ = 1;
    manager->activeReminder_ = reminder;
    manager->CloseReminder(reminder, true);
    reminder->SetReminderId(2);
    manager->alertingReminderId_ = 2;
    manager->CloseReminder(reminder, true);
    reminder->SetReminderId(3);
    manager->CloseReminder(reminder, true);
    manager->CloseReminder(reminder, false);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_006
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_006, Level1)
{
    manager->RefreshRemindersDueToSysTimeChange(0);
    manager->RefreshRemindersDueToSysTimeChange(1);
    manager->activeReminderId_ = 1;
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->activeReminder_ = reminder;
    manager->RefreshRemindersDueToSysTimeChange(1);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_007
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_007, Level1)
{
    EventFwk::Want want;
    want.SetParam(ReminderRequest::PARAM_REMINDER_ID, 10);
    manager->ShowActiveReminder(want);
    manager->CloseReminder(want, true);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->SetReminderId(10);
    manager->reminderVector_.push_back(reminder);
    manager->ShowActiveReminder(want);
    manager->activeReminderId_ = 10;
    manager->activeReminder_ = reminder;
    manager->ShowActiveReminder(want);
    manager->CloseReminder(want, true);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_008
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_008, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->TerminateAlerting(0, reminder);
    manager->TerminateAlerting(nullptr, "");
    manager->TerminateAlerting(reminder, "");
    reminder->state_ = 2;
    manager->TerminateAlerting(reminder, "");
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_009
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_009, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    manager->UpdateAndSaveReminderLocked(reminder, option);
    AdvancedNotificationService service;
    manager->SetService(&service);
    manager->ShouldAlert(nullptr);
    manager->currentUserId_ = 0;
    option->SetUid(1);
    manager->ShouldAlert(reminder);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_010
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_010, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->HandleSysTimeChange(reminder);
    manager->SetActiveReminder(nullptr);
    manager->SetActiveReminder(reminder);
    manager->SetAlertingReminder(nullptr);
    manager->SetAlertingReminder(reminder);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_011
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_011, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->SetReminderId(0);
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    manager->notificationBundleOptionMap_[10] = option;
    manager->ShowReminder(reminder, true, true, true, true);
    reminder->SetReminderId(10);
    manager->ShowReminder(reminder, true, true, true, true);
    manager->ShowReminder(reminder, true, true, true, true);
    manager->alertingReminderId_ = 1;
    manager->ShowReminder(reminder, true, true, true, true);
    manager->alertingReminderId_ = -1;
    manager->ShowReminder(reminder, true, true, true, true);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_012
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_012, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->activeReminderId_ = 10;
    manager->activeReminder_ = reminder;
    reminder->SetReminderId(10);
    manager->activeReminderId_ = 1;
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_013
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_013, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->activeReminderId_ = 10;
    manager->activeReminder_ = reminder;
    reminder->SetReminderId(10);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_014
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_014, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->SetReminderId(0);
    manager->StartRecentReminder();
    manager->StopAlertingReminder(nullptr);
    manager->alertingReminderId_ = -1;
    manager->StopAlertingReminder(reminder);
    manager->alertingReminderId_ = 1;
    manager->StopAlertingReminder(reminder);
    reminder->SetReminderId(1);
    manager->StopAlertingReminder(reminder);
    manager->Dump();
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_015
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_015, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    std::vector<sptr<ReminderRequest>> vec;
    vec.push_back(reminder);
    manager->HandleImmediatelyShow(vec, true);
    manager->HandleRefreshReminder(0, reminder);
    manager->HandleSameNotificationIdShowing(reminder);
    manager->Init(true);
    manager->InitUserId();
    manager->GetImmediatelyShowRemindersLocked(vec);
    manager->IsAllowedNotify(reminder);
    manager->IsAllowedNotify(nullptr);
    manager->IsReminderAgentReady();
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_001, Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventSubscriber>(subscriberInfo, manager);
    EventFwk::CommonEventData data;
    Want want;
    want.SetAction(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_002
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_002, Level1)
{
    auto statusChangeListener
        = std::make_shared<ReminderEventManager::SystemAbilityStatusChangeListener>(manager);
    statusChangeListener->OnAddSystemAbility(0, "");
    statusChangeListener->OnRemoveSystemAbility(0, "");
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_003
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_003, Level1)
{
    auto timeInfo = std::make_shared<ReminderTimerInfo>();
    timeInfo->SetType(0);
    timeInfo->SetRepeat(false);
    timeInfo->SetInterval(0);
    timeInfo->SetWantAgent(nullptr);
    timeInfo->action_ = ReminderRequest::REMINDER_EVENT_ALARM_ALERT;
    timeInfo->OnTrigger();
    timeInfo->action_ = ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT;
    timeInfo->OnTrigger();
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}
}  // namespace Notification
}  // namespace OHOS
