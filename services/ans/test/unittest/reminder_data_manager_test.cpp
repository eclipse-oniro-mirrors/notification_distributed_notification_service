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

#include <map>
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
#include "reminder_request_alarm.h"
#include "reminder_request.h"
#include "reminder_request_calendar.h"
#include "ability_manager_client.h"
#include "mock_ipc_skeleton.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::EventFwk;
namespace OHOS {
namespace Notification {
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderDataManager::InitInstance(nullptr);
        manager = ReminderDataManager::GetInstance();
        manager->Init(false);
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
    manager->CancelAllReminders("", -1, -1);
    manager->CancelAllReminders(-1);
    manager->IsMatched(reminder, "", -1, -1);
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
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->CheckReminderLimitExceededLocked(option, reminder);
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
    manager->OnBundleMgrServiceStart();
    manager->OnAbilityMgrServiceStart();
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
    reminder->SetReminderId(4);
    reminder->SetGroupId("");
    manager->CloseReminder(reminder, true);
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
    sptr<AdvancedNotificationService> service(new AdvancedNotificationService);
    manager->SetService(service);
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
    sptr<ReminderRequest> reminder(new ReminderRequestTimer(10));
    reminder->SetReminderId(0);
    sptr<NotificationBundleOption> option(new NotificationBundleOption());
    manager->ShowReminder(reminder, true, true, true, true);
    reminder->SetNotificationBundleOption(option);
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
 * @tc.name: ReminderDataManagerTest_016
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issuesI8CAQB
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_016, Level1)
{
    // not SystemApp
    std::vector<uint8_t> daysOfWeek;
    sptr<ReminderRequest> reminder = new ReminderRequestAlarm(0, 1, daysOfWeek);
    std::shared_ptr<ReminderRequest::ButtonWantAgent> buttonWantAgent =
        std::make_shared<ReminderRequest::ButtonWantAgent>();
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate> buttonDataShareUpdate =
        std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    reminder->SetSystemApp(false);
    reminder->SetActionButton("不再提醒", ReminderRequest::ActionButtonType::CLOSE,
        "", buttonWantAgent, buttonDataShareUpdate);
    manager->UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CLOSE);
 
    // INVALID ActionButtonType
    reminder->SetSystemApp(true);
    reminder->SetActionButton("无效的", ReminderRequest::ActionButtonType::INVALID,
        "", buttonWantAgent, buttonDataShareUpdate);
    manager->UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::INVALID);

    // actionButtonType does not exist
    std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo> actionButtonMap;
    manager->CheckUpdateConditions(reminder, ReminderRequest::ActionButtonType::CLOSE, actionButtonMap);

    // null ButtonDataShareUpdate
    reminder->SetActionButton("稍后提醒", ReminderRequest::ActionButtonType::SNOOZE, "", buttonWantAgent);
    manager->UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::SNOOZE);
 
    // not have uri
    manager->UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CLOSE);
 
    // update datashare
    sptr<ReminderRequest> reminder1 = new ReminderRequestAlarm(2, 3, daysOfWeek);
    std::shared_ptr<ReminderRequest::ButtonWantAgent> buttonWantAgent1 =
        std::make_shared<ReminderRequest::ButtonWantAgent>();
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate> buttonDataShareUpdate1 =
        std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    reminder1->SetSystemApp(true);
    reminder1->InitUserId(100);
    buttonDataShareUpdate1->uri = "datashareTest://com.acts.dataShareTest";
    buttonDataShareUpdate1->equalTo = "name<SEP:/>string<SEP:/>li<SEP;/>"
        "id<SEP:/>double<SEP:/>3.0<SEP;/>status<SEP:/>bool<SEP:/>true";
    buttonDataShareUpdate1->valuesBucket = "name<SEP:/>string<SEP:/>wang<SEP;/>"
        "id<SEP:/>double<SEP:/>4.0<SEP;/>status<SEP:/>bool<SEP:/>true<SEP;/>actionId<SEP:/>null<SEP:/>null";
    reminder1->SetActionButton("不再提醒", ReminderRequest::ActionButtonType::CLOSE, "",
        buttonWantAgent1, buttonDataShareUpdate1);
    manager->UpdateAppDatabase(reminder1, ReminderRequest::ActionButtonType::CLOSE);
    EXPECT_TRUE(reminder1->actionButtonMap_.size() > 0);
}

/**
 * @tc.name: ReminderDataManagerTest_017
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI8CDH3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_017, Level1)
{
    IPCSkeleton::SetCallingTokenID(1);
    sptr<ReminderRequest> reminder1 = new ReminderRequestTimer(10);
    sptr<ReminderRequest> reminder2 = new ReminderRequestTimer(10);
    sptr<ReminderRequest> reminder3 = new ReminderRequestTimer(10);
    int32_t oldReminderId = 1;
    reminder1->SetReminderId(1);
    reminder2->SetReminderId(2);
    reminder3->SetReminderId(3);
    reminder1->SetGroupId("123");
    reminder2->SetGroupId("123");
    reminder3->SetGroupId("124");
    sptr<NotificationBundleOption> option1 = new NotificationBundleOption();
    sptr<NotificationBundleOption> option2 = new NotificationBundleOption();
    sptr<NotificationBundleOption> option3 = new NotificationBundleOption();
    option1->SetBundleName("test");
    option2->SetBundleName("test");
    manager->PublishReminder(reminder1, option1);
    manager->PublishReminder(reminder2, option2);
    manager->PublishReminder(reminder3, option3);
    manager->CloseRemindersByGroupId(oldReminderId, "test", "123");
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(reminder2->isExpired_);
}

/**
 * @tc.name: ReminderDataManagerTest_018
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI8E7Z1
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_018, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    std::string ringUri = "123";
    reminder->SetCustomRingUri(ringUri);
    std::string getRingUri = manager->GetCustomRingUri(reminder);
    ASSERT_EQ(ringUri, getRingUri);
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

/**
 * @tc.name: ReminderEventManagerTest_004
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_004, Level1)
{
    EventFwk::Want want;
    manager->HandleCustomButtonClick(want);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->reminderVector_.push_back(reminder);
    want.SetParam(ReminderRequest::PARAM_REMINDER_ID, 10);
    manager->HandleCustomButtonClick(want);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: StartExtensionAbilityTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI92G9T
 */
HWTEST_F(ReminderDataManagerTest, StartExtensionAbilityTest_001, Level1)
{
    auto reminder1 = new ReminderRequestCalendar(10);
    bool ret1 = manager->StartExtensionAbility(reminder1, 0);
    EXPECT_TRUE(ret1);

    auto reminder2 = new ReminderRequestCalendar(10);
    auto wantInfo = std::make_shared<ReminderRequest::WantAgentInfo>();
    reminder2->SetRRuleWantAgentInfo(wantInfo);
    bool ret2 = manager->StartExtensionAbility(reminder2, 0);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.name: IsBelongToSameAppTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I97Q9Q
 */
HWTEST_F(ReminderDataManagerTest, IsBelongToSameAppTest_001, Level1)
{
    sptr<NotificationBundleOption> option1 = new NotificationBundleOption("test", 100);
    sptr<NotificationBundleOption> option2 = new NotificationBundleOption("test", 100);
    EXPECT_TRUE(manager->IsBelongToSameApp(option1, option2));

    option2->SetUid(101);
    EXPECT_FALSE(manager->IsBelongToSameApp(option1, option2));

    option2->SetUid(100);
    option2->SetBundleName("test1");
    EXPECT_FALSE(manager->IsBelongToSameApp(option1, option2));
}

/**
 * @tc.name: CheckIsSameAppTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I97Q9Q
 */
HWTEST_F(ReminderDataManagerTest, CheckIsSameAppTest_001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->InitCreatorBundleName("test");
    reminder->InitUserId(-1);
    sptr<NotificationBundleOption> option = new NotificationBundleOption("test", -1);
    EXPECT_TRUE(manager->CheckIsSameApp(reminder, option));

    reminder->InitCreatorBundleName("test1");
    EXPECT_FALSE(manager->CheckIsSameApp(reminder, option));
}

/**
 * @tc.name: CheckPulishReminder
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I97Q9Q
 */
HWTEST_F(ReminderDataManagerTest, CheckPulishReminder_0001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    sptr<NotificationBundleOption> option = new NotificationBundleOption();
    IPCSkeleton::SetCallingTokenID(0);
    ErrCode ret = manager->PublishReminder(reminder, option);
    ASSERT_EQ(ret, ERR_REMINDER_CALLER_TOKEN_INVALID);

    IPCSkeleton::SetCallingTokenID(1);
    ret = manager->PublishReminder(reminder, option);
    EXPECT_NE(ret, ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED);
}

/**
 * @tc.name: OnLanguageChanged
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I97Q9Q
 */
HWTEST_F(ReminderDataManagerTest, OnLanguageChanged_0001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    reminder->SetReminderId(10);
    std::string title = "this is title";
    std::string resource = "close";
    ReminderRequest::ActionButtonType type = ReminderRequest::ActionButtonType::CLOSE;
    reminder->SetActionButton(title, type, resource);

    manager->reminderVector_.push_back(reminder);
    manager->showedReminderVector_.push_back(reminder);

    manager->OnLanguageChanged();
    EXPECT_TRUE(reminder->actionButtonMap_[type].title == "this is title");
}

/**
 * @tc.name: ExcludeDate
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I97Q9Q
 */
HWTEST_F(ReminderDataManagerTest, ExcludeDate_0001, Level1)
{
    std::vector<uint64_t> dates;
    auto result = manager->CheckExcludeDateParam(9999, nullptr);
    EXPECT_TRUE(result == nullptr);

    auto ret = manager->AddExcludeDate(9999, 100, nullptr);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    ret = manager->DelExcludeDates(9999, nullptr);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    ret = manager->GetExcludeDates(9999, nullptr, dates);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    sptr<ReminderRequest> reminder = new ReminderRequestCalendar(10);
    reminder->InitCreatorBundleName("test1");
    reminder->InitUserId(-1);
    reminder->reminderId_ = 100;
    manager->reminderVector_.push_back(reminder);
    sptr<NotificationBundleOption> option = new NotificationBundleOption("test", -1);
    result = manager->CheckExcludeDateParam(100, option);
    EXPECT_TRUE(result == nullptr);

    reminder->InitCreatorBundleName("test");
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    result = manager->CheckExcludeDateParam(100, option);
    EXPECT_TRUE(result == nullptr);

    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    result = manager->CheckExcludeDateParam(100, option);
    EXPECT_TRUE(result == nullptr);

    reminder->repeatDaysOfWeek_ = 1;
    result = manager->CheckExcludeDateParam(100, option);
    EXPECT_TRUE(result != nullptr);

    ret = manager->AddExcludeDate(100, 100, option);
    EXPECT_TRUE(ret == ERR_OK);

    ret = manager->DelExcludeDates(100, option);
    EXPECT_TRUE(ret == ERR_OK);

    ret = manager->GetExcludeDates(100, option, dates);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: InitStartExtensionAbility
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, InitStartExtensionAbility_0001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestCalendar(10);
    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
    uint64_t now = calendar->GetNowInstantMilli();
    calendar->SetDateTime(now-50000);
    calendar->SetEndDateTime(now+50000);
    manager->reminderVector_.push_back(calendar);
    manager->Init(true);
    EXPECT_TRUE(!manager->reminderVector_.empty());
}

/**
 * @tc.name: ReminderNotificationSubscriber_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ReminderNotificationSubscriber_00001, Level1)
{
    ReminderEventManager::ReminderNotificationSubscriber test(manager);
    sptr<NotificationRequest> notificationReq = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(notificationReq);
    test.OnCanceled(notification, nullptr, NotificationConstant::CANCEL_REASON_DELETE);
    SUCCEED();

    test.OnCanceled(nullptr, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("TEST_1");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("TEST_NOTIFICATION_1");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("REMINDER_NOTIFICATION_1");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("REMINDER_AGENT_INFO");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();

    notificationReq->SetLabel("REMINDER_AGENT_0");
    test.OnCanceled(notification, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
    SUCCEED();
}

/**
 * @tc.name: CancelAllReminders_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, CancelAllReminders_00001, Level1)
{
    int32_t ret = manager->CancelAllReminders("", -1, -1);
    EXPECT_TRUE(ret == ERR_OK);

    ret = manager->CancelAllReminders("com.example.simple", 100, 20020152);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: GetVaildReminders_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, GetVaildReminders_00001, Level1)
{
    sptr<ReminderRequest> reminder1 = new ReminderRequestTimer(static_cast<uint64_t>(50));
    reminder1->InitCreatorBundleName("test_getvalid");
    reminder1->InitCreatorUid(98765);
    reminder1->InitBundleName("test_getvalid");
    reminder1->InitUid(98765);
    sptr<NotificationBundleOption> option1 = new NotificationBundleOption("test_getvalid", 98765);
    manager->PublishReminder(reminder1, option1);
    reminder1->SetExpired(false);

    sptr<ReminderRequest> reminder2 = new ReminderRequestTimer(51);
    reminder2->InitCreatorBundleName("test_getvalid");
    reminder2->InitCreatorUid(98765);
    reminder2->InitBundleName("test_getvalid");
    reminder2->InitUid(98765);
    reminder2->SetExpired(true);
    sptr<NotificationBundleOption> option2 = new NotificationBundleOption("test_getvalid", 98765);
    manager->PublishReminder(reminder2, option2);
    
    std::vector<sptr<ReminderRequest>> reminders;
    manager->GetValidReminders(option2, reminders);
    EXPECT_TRUE(reminders.size() == 1);
}

/**
 * @tc.name: IsMatched_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, IsMatched_00001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(50);
    reminder->InitCreatorBundleName("test_IsMatched");
    reminder->InitCreatorUid(98765);
    reminder->InitBundleName("test_IsMatched");
    reminder->InitUid(98765);
    reminder->InitUserId(100);
    bool ret = manager->IsMatched(reminder, "test_IsMatched", 101, 98765);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, "allPackages", 100, 98765);
    EXPECT_EQ(ret, true);
    ret = manager->IsMatched(reminder, "test_IsMatched2", 100, 98765);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, "test_IsMatched", 100, -1);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, "test_IsMatched", 100, 98766);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, "test_IsMatched", 100, 98765);
    EXPECT_EQ(ret, true);
}
}  // namespace Notification
}  // namespace OHOS
