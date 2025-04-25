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

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "reminder_data_manager.h"
#include "reminder_event_manager.h"
#include "reminder_request_timer.h"
#include "reminder_request_alarm.h"
#include "reminder_request.h"
#include "reminder_request_adaptation.h"
#include "reminder_request_calendar.h"
#include "ability_manager_client.h"
#include "mock_ipc_skeleton.h"
#include "reminder_datashare_helper.h"
#include "reminder_config_change_observer.h"
#include "reminder_calendar_share_table.h"
#include "reminder_timer_info.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;
namespace OHOS {
namespace Notification {
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderDataManager::InitInstance();
        manager = ReminderDataManager::GetInstance();
        manager->RegisterConfigurationObserver();
        manager->Init();
    }
    static void TearDownTestCase()
    {
        manager->showedReminderVector_.clear();
        manager = nullptr;
    }
    void SetUp() {};
    void TearDown() {};

public:
    static std::shared_ptr<ReminderDataManager> manager;
};

std::shared_ptr<ReminderDataManager> ReminderDataManagerTest::manager = nullptr;

/**
 * @tc.name: GetVaildReminders_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, GetVaildReminders_00001, Level1)
{
    IPCSkeleton::SetCallingTokenID(100);
    manager->store_->Init();
    int32_t callingUid = 98765;
    sptr<ReminderRequest> reminder1 = new ReminderRequestTimer(static_cast<uint64_t>(50));
    reminder1->InitCreatorBundleName("test_getvalid");
    reminder1->InitCreatorUid(callingUid);
    reminder1->InitBundleName("test_getvalid");
    reminder1->InitUid(callingUid);
    reminder1->SetExpired(false);
    manager->PublishReminder(reminder1, callingUid);

    sptr<ReminderRequest> reminder2 = new ReminderRequestTimer(51);
    reminder2->InitCreatorBundleName("test_getvalid");
    reminder2->InitCreatorUid(callingUid);
    reminder2->InitBundleName("test_getvalid");
    reminder2->InitUid(callingUid);
    reminder2->SetExpired(true);
    manager->PublishReminder(reminder2, callingUid);
    
    std::vector<ReminderRequestAdaptation> reminders;
    manager->GetValidReminders(callingUid, reminders);
    EXPECT_TRUE(reminders.size() >= 0);
}

/**
 * @tc.name: ReminderDataManagerTest_001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_001, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    int32_t reminderId = -1;
    manager->PublishReminder(reminder, reminderId);
    manager->CancelReminder(reminderId, -1);
    manager->CancelAllReminders("", -1, -1);
    manager->CancelAllReminders(-1);
    manager->IsMatched(reminder, -1, -1, true);
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
    int32_t callingUid = -1;
    std::vector<ReminderRequestAdaptation> vec;
    manager->GetValidReminders(callingUid, vec);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);

    manager->CheckReminderLimitExceededLocked(callingUid, reminder);
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
    manager->showedReminderVector_.clear();
    int32_t callingUid = -1;
    manager->OnProcessDiedLocked(callingUid);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->CreateTimerInfo(ReminderDataManager::TimerType::TRIGGER_TIMER, reminder);
    manager->CreateTimerInfo(ReminderDataManager::TimerType::ALERTING_TIMER, reminder);
    manager->FindReminderRequestLocked(0, false);
    reminder->SetReminderId(10);
    manager->reminderVector_.push_back(reminder);
    manager->FindReminderRequestLocked(10, false);
    manager->FindReminderRequestLocked(10, false);
    manager->FindReminderRequestLocked(10, false);
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
    int32_t callingUid = -1;
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(10);
    manager->UpdateAndSaveReminderLocked(reminder);
    sptr<ReminderAgentService> service(new ReminderAgentService);
    manager->ShouldAlert(nullptr);
    manager->currentUserId_ = 0;
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
    manager->Init();
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
    int32_t callingUid = 1;
    reminder1->SetReminderId(1);
    reminder2->SetReminderId(2);
    reminder3->SetReminderId(3);
    reminder1->SetGroupId("123");
    reminder2->SetGroupId("123");
    reminder3->SetGroupId("124");
    manager->PublishReminder(reminder1, callingUid);
    manager->PublishReminder(reminder2, callingUid);
    manager->PublishReminder(reminder3, callingUid);
    manager->CloseRemindersByGroupId(1, "test", "123");
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
    std::string getRingUri = reminder->GetCustomRingUri();
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
    int32_t uidSrc = 100;
    int32_t uidTar = 100;
    EXPECT_TRUE(manager->IsBelongToSameApp(uidSrc, uidTar));

    uidTar = 101;
    EXPECT_FALSE(manager->IsBelongToSameApp(uidSrc, uidTar));
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
    int32_t callingUid = 100;
    reminder->InitCreatorUid(callingUid);
    EXPECT_TRUE(manager->CheckIsSameApp(reminder, callingUid));

    reminder->InitCreatorUid(-1);
    EXPECT_FALSE(manager->CheckIsSameApp(reminder, callingUid));
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
    int32_t callingUid = -1;
    IPCSkeleton::SetCallingTokenID(0);
    ErrCode ret = manager->PublishReminder(reminder, callingUid);
    ASSERT_EQ(ret, ERR_REMINDER_CALLER_TOKEN_INVALID);

    IPCSkeleton::SetCallingTokenID(1);
    ret = manager->PublishReminder(reminder, callingUid);
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
    std::vector<int64_t> dates;
    int32_t callingUid = -1;
    auto result = manager->CheckExcludeDateParam(9999, callingUid);
    EXPECT_TRUE(result == nullptr);

    auto ret = manager->AddExcludeDate(9999, 100, callingUid);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    ret = manager->DelExcludeDates(9999, callingUid);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    ret = manager->GetExcludeDates(9999, callingUid, dates);
    EXPECT_TRUE(ret == ERR_REMINDER_NOT_EXIST);

    sptr<ReminderRequest> reminder = new ReminderRequestCalendar(10);
    reminder->InitCreatorBundleName("test1");
    reminder->InitUserId(-1);
    reminder->reminderId_ = 100;
    manager->reminderVector_.push_back(reminder);
    result = manager->CheckExcludeDateParam(100, callingUid);
    EXPECT_TRUE(result == nullptr);

    reminder->InitCreatorBundleName("test");
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    result = manager->CheckExcludeDateParam(100, callingUid);
    EXPECT_TRUE(result == nullptr);

    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    result = manager->CheckExcludeDateParam(100, callingUid);
    EXPECT_TRUE(result == nullptr);

    reminder->repeatDaysOfWeek_ = 1;
    result = manager->CheckExcludeDateParam(100, callingUid);
    EXPECT_TRUE(result != nullptr);

    ret = manager->AddExcludeDate(100, 100, callingUid);
    EXPECT_TRUE(ret == ERR_OK);

    ret = manager->DelExcludeDates(100, callingUid);
    EXPECT_TRUE(ret == ERR_OK);

    ret = manager->GetExcludeDates(100, callingUid, dates);
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
    manager->Init();
    EXPECT_TRUE(!manager->reminderVector_.empty());
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

    ret = manager->CancelAllReminders("", 100, 20020152);
    EXPECT_TRUE(ret == ERR_OK);
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
    bool ret = manager->IsMatched(reminder, 101, 98765, true);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, 100, 98765, false);
    EXPECT_EQ(ret, true);
    ret = manager->IsMatched(reminder, 100, -1, false);
    EXPECT_EQ(ret, false);
    ret = manager->IsMatched(reminder, 100, -1, true);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ReminderEventManager_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManager_001, Level1)
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
    
    EventFwk::Want want;
    want.SetParam(ReminderRequest::PARAM_REMINDER_ID, 0);
    AppExecFwk::ElementName element("", "test", "EntryAbility");
    want.SetElement(element);
    subscriber->HandlePackageRemove(want);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: IsMatched_00001
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManager_002, Level1)
{
    auto statusChangeListener
        = std::make_shared<ReminderEventManager::SystemAbilityStatusChangeListener>(manager);
    statusChangeListener->OnAddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, "");
    statusChangeListener->OnAddSystemAbility(APP_MGR_SERVICE_ID, "");
    statusChangeListener->OnAddSystemAbility(ABILITY_MGR_SERVICE_ID, "");
    statusChangeListener->OnAddSystemAbility(-1, "");
    statusChangeListener->OnRemoveSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, "");
    statusChangeListener->OnRemoveSystemAbility(APP_MGR_SERVICE_ID, "");
    statusChangeListener->OnRemoveSystemAbility(ABILITY_MGR_SERVICE_ID, "");
    statusChangeListener->OnRemoveSystemAbility(-1, "");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_005
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_005, Level1)
{
    MatchingSkills customMatchingSkills;
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLICK_ALERT);
    CommonEventSubscribeInfo subscriberInfo(customMatchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventCustomSubscriber>(subscriberInfo, manager);
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
    want.SetAction(ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    want.SetAction(ReminderRequest::REMINDER_EVENT_CLICK_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    system("rm -rf /data/service/el1/public/notification/");
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_006
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderEventManagerTest_006, Level1)
{
    std::shared_ptr<ReminderDataManager> data;
    ReminderEventManager::ReminderNotificationSubscriber subscriber(data);
    subscriber.OnCanceled(nullptr, nullptr, NotificationConstant::PACKAGE_REMOVE_REASON_DELETE);
    subscriber.OnCanceled(nullptr, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    request->SetAutoDeletedTime(100);
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    request->SetLabel("REMINDER_AGENT");
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_020
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_020, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(500);
    manager->CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::CLOSE);
    reminder->InitBundleName("test");
    manager->CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::CLOSE);

    manager->isReminderAgentReady_ = false;
    manager->OnUnlockScreen();
    manager->isReminderAgentReady_ = true;
    auto queue = manager->queue_;
    manager->queue_ = nullptr;
    manager->OnUnlockScreen();
    manager->queue_ = queue;

    EventFwk::Want want;
    manager->TerminateAlerting(want);
    manager->SnoozeReminder(want);
    manager->ClickReminder(want);
    manager->SnoozeReminderImpl(reminder);
    manager->OnLoadReminderEvent();
    manager->GetFullPath("1p");
    manager->PlaySoundAndVibration(nullptr);
    manager->RemoveReminderLocked(500, true);
    manager->RemoveReminderLocked(500, false);
    manager->ResetStates(ReminderDataManager::TimerType::ALERTING_TIMER);
    manager->ResetStates(static_cast<ReminderDataManager::TimerType>(100));
    manager->StopTimer(static_cast<ReminderDataManager::TimerType>(100));
    manager->ConnectAppMgr();
    manager->ConnectAppMgr();
    manager->OnRemoveAppMgr();
    Global::Resource::ResourceManager::RawFileDescriptor desc;
    manager->GetCustomRingFileDesc(reminder, desc);
    manager->CloseCustomRingFileDesc(500, "");
    manager->HandleAutoDeleteReminder(500, 100, 123456);
    std::map<std::string, sptr<ReminderRequest>> reminders;
    reminders["500"] = reminder;
    manager->UpdateShareReminders(reminders);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_021
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_021, Level1)
{
    ReminderDataShareHelper::GetInstance().RegisterObserver();
    ReminderDataShareHelper::GetInstance().RegisterObserver();
    ReminderDataShareHelper::GetInstance().Update(1, 1);
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    DataShare::DataShareObserver::ChangeInfo info;
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    info.valueBuckets_.resize(1);
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    ReminderDataShareHelper::GetInstance().UnRegisterObserver();
    ReminderDataShareHelper::GetInstance().UnRegisterObserver();

    ReminderDataShareHelper::ReminderDataObserver observer;
    DataShare::DataShareObserver::ChangeInfo info1;
    info1.changeType_ = DataShare::DataShareObserver::ChangeType::INSERT;
    observer.OnChange(info1);
    info1.changeType_ = DataShare::DataShareObserver::ChangeType::UPDATE;
    observer.OnChange(info1);
    info1.changeType_ = DataShare::DataShareObserver::ChangeType::DELETE;
    observer.OnChange(info1);
    info1.changeType_ = DataShare::DataShareObserver::ChangeType::OTHER;
    observer.OnChange(info1);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_022
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_022, Level1)
{
    ReminderConfigChangeObserver observer;
    AppExecFwk::Configuration config;
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, "");
    observer.OnConfigurationUpdated(config);
    config.RemoveItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, "test");
    observer.languageInfo_ = "test";
    observer.OnConfigurationUpdated(config);
    observer.languageInfo_ = "1111";
    observer.OnConfigurationUpdated(config);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_023
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_023, Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequestTimer(500);
    auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    auto datashare = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    reminder->SetActionButton("title", ReminderRequest::ActionButtonType::CLOSE, "resource",
        buttonWantAgent, datashare);
    manager->IsActionButtonDataShareValid(reminder, 0);
    datashare->uri = "1111";
    manager->IsActionButtonDataShareValid(reminder, 0);

    std::unordered_map<std::string, int32_t> limits;
    int32_t totalCount = 0;
    reminder->InitUid(1);
    reminder->SetTriggerTimeInMilli(100);
    manager->CheckShowLimit(limits, totalCount, reminder);
    manager->CheckShowLimit(limits, totalCount, reminder);
    limits["1_100"] = 100;
    manager->CheckShowLimit(limits, totalCount, reminder);
    totalCount = 1000;
    manager->CheckShowLimit(limits, totalCount, reminder);

    sleep(1);
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        manager->showedReminderVector_.push_back(reminder);
    }
    manager->HandleAutoDeleteReminder(231, 232, 233);
    reminder->InitUid(232);
    manager->HandleAutoDeleteReminder(231, 232, 233);
    reminder->SetNotificationId(231);
    manager->HandleAutoDeleteReminder(231, 232, 233);
    reminder->SetAutoDeletedTime(233);
    manager->HandleAutoDeleteReminder(231, 232, 233);
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        manager->showedReminderVector_.clear();
    }
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_024
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_024, Level1)
{
    sptr<ReminderRequest> timer = new ReminderRequestTimer(500);
    timer->SetReminderId(241);
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar();
    calendar->SetReminderId(242);
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.push_back(timer);
        manager->reminderVector_.push_back(calendar);
    }
    std::map<std::string, sptr<ReminderRequest>> reminders;
    manager->UpdateShareReminders(reminders);
    timer->SetShare(true);
    calendar->SetShare(true);
    manager->UpdateShareReminders(reminders);
    calendar->SetIdentifier("242");
    reminders["242"] = calendar;
    manager->UpdateShareReminders(reminders);
    manager->LoadShareReminders();
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.clear();
    }
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_025
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_025, Level1)
{
    DataShare::DataShareObserver::ChangeInfo info;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);
    info.valueBuckets_.resize(1);

    DataShare::DataShareObserver::ChangeInfo::Value alarmTime = static_cast<double>(251);
    info.valueBuckets_[0][ReminderCalendarShareTable::ALARM_TIME] = alarmTime;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value id = static_cast<double>(252);
    info.valueBuckets_[0][ReminderCalendarShareTable::ID] = id;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value eventId = static_cast<double>(253);
    info.valueBuckets_[0][ReminderCalendarShareTable::EVENT_ID] = eventId;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value slotType = static_cast<double>(0);
    info.valueBuckets_[0][ReminderCalendarShareTable::SLOT_TYPE] = slotType;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value title = std::string("25");
    info.valueBuckets_[0][ReminderCalendarShareTable::TITLE] = title;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value content = std::string("255");
    info.valueBuckets_[0][ReminderCalendarShareTable::CONTENT] = content;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value buttons = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::BUTTONS] = buttons;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value wantAgent = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::WANT_AGENT] = wantAgent;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value identifier = std::string("256");
    info.valueBuckets_[0][ReminderCalendarShareTable::IDENTIFIER] = identifier;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);

    DataShare::DataShareObserver::ChangeInfo::Value ends = static_cast<double>(1737948039000);
    info.valueBuckets_[0][ReminderCalendarShareTable::END] = ends;
    ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_026
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_026, Level1)
{
    ReminderTimerInfo info;
    info.OnTrigger();
    info.SetReminderTimerType(ReminderTimerInfo::ReminderTimerType::REMINDER_TIMER_LOAD);
    info.OnTrigger();
    info.SetReminderTimerType(static_cast<ReminderTimerInfo::ReminderTimerType>(9));
    info.OnTrigger();
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_027
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_027, Level1)
{
    sptr<ReminderRequest> timer = new ReminderRequestTimer(500);
    timer->SetReminderId(271);
    auto wantInfo = timer->wantAgentInfo_;
    timer->wantAgentInfo_ = nullptr;
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.push_back(timer);
    }
    EventFwk::Want want;
    want.SetParam(ReminderRequest::PARAM_REMINDER_ID, 271);
    manager->ClickReminder(want);
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.clear();
        manager->reminderVector_.push_back(timer);
    }
    timer->wantAgentInfo_ = wantInfo;
    manager->ClickReminder(want);
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.clear();
        manager->reminderVector_.push_back(timer);
    }
    timer->wantAgentInfo_->pkgName = "test";
    manager->ClickReminder(want);
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.clear();
        manager->reminderVector_.push_back(timer);
    }
    timer->SetSystemApp(true);
    manager->HandleCustomButtonClick(want);
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        manager->reminderVector_.clear();
    }
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_028
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_028, Level1)
{
    sptr<ReminderRequest> timer = new ReminderRequestTimer(500);
    timer->SetReminderId(281);
    sptr<ReminderRequest> timer2 = new ReminderRequestTimer(500);
    timer2->SetReminderId(282);
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        manager->showedReminderVector_.push_back(timer);
        manager->showedReminderVector_.push_back(timer2);
    }
    manager->RemoveFromShowedReminders(timer);
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        manager->showedReminderVector_.clear();
    }
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderDataManagerTest_029
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_029, Level1)
{
    manager->InitShareReminders(true);
    manager->InitShareReminders(false);
    manager->isReminderAgentReady_ = false;
    manager->OnUserSwitch(1);
    sleep(1);
    manager->isReminderAgentReady_ = true;
    auto queue = std::move(manager->queue_);
    manager->OnUserSwitch(1);
    sleep(1);
    manager->queue_ = std::move(queue);
    manager->OnUserSwitch(1);
    EXPECT_TRUE(manager != nullptr);
    sleep(1);
}

/**
 * @tc.name: ReminderDataManagerTest_030
 * @tc.desc: Reminder data manager test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataManagerTest, ReminderDataManagerTest_030, Level1)
{
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar(300);
    calendar->triggerTimeInMilli_ = 0;
    manager->UpdateAndSaveReminderLocked(calendar, false);
    EXPECT_TRUE(calendar->isExpired_ == true);
    calendar->triggerTimeInMilli_ = ::time(nullptr) * 1000 + 30 * 60 * 1000;
    manager->UpdateAndSaveReminderLocked(calendar, true);
    calendar->reminderId_ = 301;
    manager->UpdateAndSaveReminderLocked(calendar, true);
    calendar->reminderId_ = 300;
    calendar->isShare_ = true;
    manager->UpdateAndSaveReminderLocked(calendar, true);
    calendar->isShare_ = false;
    manager->UpdateAndSaveReminderLocked(calendar, true);
    EXPECT_TRUE(manager != nullptr);
}
}  // namespace Notification
}  // namespace OHOS
