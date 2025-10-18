/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "reminder_event_manager.h"

#include "input_manager.h"
#include "common_event_support.h"
#include "mock_service_registry.h"
#include "mock_notification_helper.h"
#include "mock_reminder_data_manager.h"

using namespace testing::ext;
namespace OHOS::Notification {
void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent);

class ReminderEventManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ReminderEventManagerTest_001
 * @tc.desc: test ReminderEventManager::Init function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_001, Level1)
{
    ReminderDataManager::InitInstance();
    auto manager = std::make_shared<ReminderEventManager>();
    manager->Init();
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_002
 * @tc.desc: test ReminderEventManager::SubscribeEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_002, Level1)
{
    auto manager = std::make_shared<ReminderEventManager>();
    MockNotificationHelper::MockSubscribeCommonEvent(false);
    manager->SubscribeEvent();
    MockNotificationHelper::MockSubscribeCommonEvent(true);
    manager->SubscribeEvent();
    MockNotificationHelper::MockSubscribeNotification(-1);
    manager->SubscribeEvent();
    MockNotificationHelper::MockSubscribeNotification(ERR_OK);
    manager->SubscribeEvent();
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_003
 * @tc.desc: test ReminderEventManager::SubscribeSystemAbility function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_003, Level1)
{
    auto manager = std::make_shared<ReminderEventManager>();
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    manager->SubscribeSystemAbility(APP_MGR_SERVICE_ID);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    manager->SubscribeSystemAbility(APP_MGR_SERVICE_ID);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_004
 * @tc.desc: test ReminderEventManager::SubscribeKeyEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_004, Level1)
{
    auto manager = std::make_shared<ReminderEventManager>();
    manager->SubscribeKeyEvent(MMI::KeyEvent::KEYCODE_VOLUME_UP);
    EXPECT_TRUE(manager != nullptr);
}

/**
 * @tc.name: ReminderEventManagerTest_005
 * @tc.desc: test ReminderEventSubscriber::OnReceiveEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_005, Level1)
{
    MockReminderDataManager::ResetFlag();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventSubscriber>(subscriberInfo);

    EventFwk::CommonEventData data;
    EventFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    data.SetWant(want);
    auto manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCancelAllReminders_ == false);

    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCancelAllReminders_ == true);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callRefreshRemindersDueToSysTimeChange_ == true);

    MockReminderDataManager::ResetFlag();
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCancelAllReminders_ == true);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callOnProcessDiedLocked_ == true);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callRefreshRemindersDueToSysTimeChange_ == true);
}

/**
 * @tc.name: ReminderEventManagerTest_006
 * @tc.desc: test ReminderEventSubscriber::OnReceiveEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_006, Level1)
{
    MockReminderDataManager::ResetFlag();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    matchingSkills.AddEvent("common.event.UNLOCK_SCREEN");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventSubscriber>(subscriberInfo);

    EventFwk::CommonEventData data;
    EventFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callOnUserSwitch_ == true);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callOnUserRemove_ == true);

    want.SetAction("common.event.UNLOCK_SCREEN");
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callOnUnlockScreen_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCancelAllReminders_ == false);
}

/**
 * @tc.name: ReminderEventManagerTest_007
 * @tc.desc: test ReminderEventCustomSubscriber::OnReceiveEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_007, Level1)
{
    MockReminderDataManager::ResetFlag();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventCustomSubscriber>(subscriberInfo);

    EventFwk::CommonEventData data;
    EventFwk::Want want;
    want.SetAction(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    data.SetWant(want);
    auto manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callShowActiveReminder_ == false);

    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callShowActiveReminder_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCloseReminder_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callSnoozeReminder_ == true);
}

/**
 * @tc.name: ReminderEventManagerTest_008
 * @tc.desc: test ReminderEventCustomSubscriber::OnReceiveEvent function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_008, Level1)
{
    MockReminderDataManager::ResetFlag();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION);
    matchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLICK_ALERT);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto subscriber = std::make_shared<ReminderEventManager::ReminderEventCustomSubscriber>(subscriberInfo);

    EventFwk::CommonEventData data;
    EventFwk::Want want;
    want.SetAction(ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callHandleCustomButtonClick_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callCloseReminder_ == true);

    want.SetAction(ReminderRequest::REMINDER_EVENT_CLICK_ALERT);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callClickReminder_ == true);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_TRUE(MockReminderDataManager::callShowActiveReminder_ == false);
}

/**
 * @tc.name: ReminderEventManagerTest_009
 * @tc.desc: test SystemAbilityStatusChangeListener
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_009, Level1)
{
    MockReminderDataManager::ResetFlag();
    auto listener = std::make_shared<ReminderEventManager::SystemAbilityStatusChangeListener>();
    // test OnAddSystemAbility
    auto manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    listener->OnAddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, "");
    EXPECT_TRUE(MockReminderDataManager::callOnBundleMgrServiceStart_ == false);

    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
    listener->OnAddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, "");
    EXPECT_TRUE(MockReminderDataManager::callOnBundleMgrServiceStart_ == true);

    listener->OnAddSystemAbility(APP_MGR_SERVICE_ID, "");
    listener->OnAddSystemAbility(ABILITY_MGR_SERVICE_ID, "");
    listener->OnAddSystemAbility(-1, "");
    EXPECT_TRUE(MockReminderDataManager::callOnAbilityMgrServiceStart_ == true);

    // test OnRemoveSystemAbility
    manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    listener->OnRemoveSystemAbility(APP_MGR_SERVICE_ID, "");
    EXPECT_TRUE(MockReminderDataManager::callOnRemoveAppMgr_ == false);

    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
    listener->OnRemoveSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, "");
    listener->OnRemoveSystemAbility(ABILITY_MGR_SERVICE_ID, "");
    listener->OnRemoveSystemAbility(APP_MGR_SERVICE_ID, "");
    listener->OnRemoveSystemAbility(-1, "");
    EXPECT_TRUE(MockReminderDataManager::callOnRemoveAppMgr_ == true);
}

/**
 * @tc.name: ReminderEventManagerTest_010
 * @tc.desc: test ReminderNotificationSubscriber::OnCanceled test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_010, Level1)
{
    MockReminderDataManager::ResetFlag();
    ReminderEventManager::ReminderNotificationSubscriber subscriber;
    // test deleteReason
    subscriber.OnCanceled(nullptr, nullptr, NotificationConstant::PACKAGE_REMOVE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == false);

    // test notification
    subscriber.OnCanceled(nullptr, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == false);

    // test autoDeletedTime
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == false);

    request->SetAutoDeletedTime(100);
    // test label
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == false);

    request->SetLabel("REMINDER_AGENT");
    // test manager
    auto manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == false);

    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
    subscriber.OnCanceled(notification, nullptr, NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    EXPECT_TRUE(MockReminderDataManager::callHandleAutoDeleteReminder_ == true);
}

/**
 * @tc.name: ReminderEventManagerTest_011
 * @tc.desc: test OnInputEvent test
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderEventManagerTest, ReminderEventManagerTest_011, Level1)
{
    // test null
    OnInputEvent(nullptr);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == false);
    // test keyCode
    auto event = MMI::KeyEvent::Create();
    event->SetKeyCode(1);
    OnInputEvent(event);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == false);

    event->SetKeyCode(MMI::KeyEvent::KEYCODE_VOLUME_UP);
    OnInputEvent(event);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == true);

    MockReminderDataManager::ResetFlag();
    event->SetKeyCode(MMI::KeyEvent::KEYCODE_VOLUME_DOWN);
    OnInputEvent(event);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == true);

    MockReminderDataManager::ResetFlag();
    event->SetKeyCode(MMI::KeyEvent::KEYCODE_POWER);
    OnInputEvent(event);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == true);

    MockReminderDataManager::ResetFlag();
    auto manager = std::move(ReminderDataManager::REMINDER_DATA_MANAGER);
    OnInputEvent(event);
    EXPECT_TRUE(MockReminderDataManager::callTerminateAlerting_ == false);
    ReminderDataManager::REMINDER_DATA_MANAGER = std::move(manager);
}
}  // namespace OHOS::Notification