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

#include "reminder_event_manager.h"

#include "ans_log_wrapper.h"
#include "reminder_data_manager.h"
#include "reminder_bundle_manager_helper.h"

#include "ipc_skeleton.h"
#include "input_manager.h"
#include "notification_helper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"

using namespace OHOS::EventFwk;
namespace OHOS::Notification {
static constexpr const char* UNLOCK_SCREEN_EVENT = "common.event.UNLOCK_SCREEN";

void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent)
{
    if (keyEvent == nullptr) {
        return;
    }

    int32_t keyCode = keyEvent->GetKeyCode();
    if (keyCode == MMI::KeyEvent::KEYCODE_VOLUME_UP || keyCode == MMI::KeyEvent::KEYCODE_VOLUME_DOWN ||
        keyCode == MMI::KeyEvent::KEYCODE_POWER) {
        auto manager = ReminderDataManager::GetInstance();
        if (manager == nullptr) {
            return;
        }
        manager->TerminateAlerting();
    }
}

ReminderEventManager& ReminderEventManager::GetInstance()
{
    static ReminderEventManager instance;
    return instance;
}

void ReminderEventManager::Init()
{
    SubscribeEvent();
    SubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    SubscribeSystemAbility(APP_MGR_SERVICE_ID);
    SubscribeSystemAbility(ABILITY_MGR_SERVICE_ID);
    SubscribeKeyEvent(MMI::KeyEvent::KEYCODE_VOLUME_UP);
    SubscribeKeyEvent(MMI::KeyEvent::KEYCODE_VOLUME_DOWN);
    SubscribeKeyEvent(MMI::KeyEvent::KEYCODE_POWER);
}

void ReminderEventManager::SubscribeEvent()
{
    MatchingSkills customMatchingSkills;
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLOSE_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT);
    customMatchingSkills.AddEvent(ReminderRequest::REMINDER_EVENT_CLICK_ALERT);
    CommonEventSubscribeInfo customSubscriberInfo(customMatchingSkills);
    customSubscriberInfo.SetPermission("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    customSubscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto customSubscriber = std::make_shared<ReminderEventCustomSubscriber>(customSubscriberInfo);

    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto subscriber = std::make_shared<ReminderEventSubscriber>(subscriberInfo);

    MatchingSkills screenMatchingSkills;
    screenMatchingSkills.AddEvent(UNLOCK_SCREEN_EVENT);
    CommonEventSubscribeInfo screenSubscriberInfo(screenMatchingSkills);
    screenSubscriberInfo.SetPublisherBundleName(AppExecFwk::Constants::SCENE_BOARD_BUNDLE_NAME);
    auto screenSubscriber = std::make_shared<ReminderEventSubscriber>(screenSubscriberInfo);

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (CommonEventManager::SubscribeCommonEvent(subscriber) &&
        CommonEventManager::SubscribeCommonEvent(customSubscriber) &&
        CommonEventManager::SubscribeCommonEvent(screenSubscriber)) {
        ANSR_LOGD("SubscribeCommonEvent ok.");
    } else {
        ANSR_LOGW("SubscribeCommonEvent failed.");
    }
    IPCSkeleton::SetCallingIdentity(identity);

    subscriber_ = std::make_shared<ReminderNotificationSubscriber>();
    if (NotificationHelper::SubscribeNotification(*subscriber_) != ERR_OK) {
        ANSR_LOGW("SubscribeNotification failed.");
    }
}

void ReminderEventManager::SubscribeSystemAbility(const int32_t systemAbilityId)
{
    sptr<SystemAbilityStatusChangeListener> statusChangeListener
        = new (std::nothrow) SystemAbilityStatusChangeListener();
    if (statusChangeListener == nullptr) {
        ANSR_LOGE("Failed to create statusChangeListener due to no memory.");
        return;
    }
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        ANSR_LOGE("GetSystemAbilityManager is null.");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(systemAbilityId, statusChangeListener);
    if (ret != ERR_OK) {
        ANSR_LOGW("SubscribeSystemAbility: %{public}d failed", systemAbilityId);
    }
}

void ReminderEventManager::SubscribeKeyEvent(const int32_t keyCode)
{
    auto keyOption = std::make_shared<MMI::KeyOption>();
    keyOption->SetFinalKey(keyCode);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetRepeat(false);
    std::function<void(std::shared_ptr<MMI::KeyEvent>)> callback = std::bind(&OnInputEvent, std::placeholders::_1);
    MMI::InputManager::GetInstance()->SubscribeKeyEvent(keyOption, callback);
}

ReminderEventManager::ReminderEventSubscriber::ReminderEventSubscriber(
    const CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

ReminderEventManager::ReminderEventCustomSubscriber::ReminderEventCustomSubscriber(
    const CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

void ReminderEventManager::ReminderEventCustomSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    Want want = data.GetWant();
    std::string action = want.GetAction();
    ANSR_LOGI("Recieved common event:%{public}s", action.c_str());
    if (action == ReminderRequest::REMINDER_EVENT_ALARM_ALERT) {
        manager->ShowActiveReminder(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT) {
        manager->TerminateAlerting(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CLOSE_ALERT) {
        manager->CloseReminder(want, true);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT) {
        manager->SnoozeReminder(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT) {
        manager->HandleCustomButtonClick(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION) {
        manager->CloseReminder(want, false, false);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CLICK_ALERT) {
        manager->ClickReminder(want);
        return;
    }
}

void ReminderEventManager::ReminderEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    Want want = data.GetWant();
    std::string action = want.GetAction();
    ANSR_LOGD("Recieved common event:%{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        AppExecFwk::ElementName ele = want.GetElement();
        std::string bundleName = ele.GetBundleName();
        int32_t userId = want.GetIntParam(AppExecFwk::Constants::USER_ID, -1);
        int32_t uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);
        manager->CancelAllReminders(bundleName, userId, uid,
            action == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED) {
        manager->RefreshRemindersDueToSysTimeChange(ReminderDataManager::TIME_ZONE_CHANGE);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_TIME_CHANGED) {
        manager->RefreshRemindersDueToSysTimeChange(ReminderDataManager::DATE_TIME_CHANGE);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        manager->OnUserSwitch(data.GetCode());
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        manager->OnUserRemove(data.GetCode());
        return;
    }
    if (action.compare(UNLOCK_SCREEN_EVENT) == 0) {
        manager->OnUnlockScreen();
    }
}

void ReminderEventManager::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    switch (systemAbilityId) {
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID:
            ANSR_LOGD("AddSystemAbility: BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.");
            manager->OnBundleMgrServiceStart();
            break;
        case APP_MGR_SERVICE_ID:
            ANSR_LOGD("AddSystemAbility: APP_MGR_SERVICE_ID.");
            break;
        case ABILITY_MGR_SERVICE_ID:
            ANSR_LOGD("AddSystemAbility: ABILITY_MGR_SERVICE_ID.");
            manager->OnAbilityMgrServiceStart();
            break;
        default:
            break;
    }
}

void ReminderEventManager::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    switch (systemAbilityId) {
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID:
            ANSR_LOGD("RemoveSystemAbility: BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.");
            break;
        case APP_MGR_SERVICE_ID:
            ANSR_LOGD("RemoveSystemAbility: APP_MGR_SERVICE_ID.");
            manager->OnRemoveAppMgr();
            break;
        case ABILITY_MGR_SERVICE_ID:
            ANSR_LOGD("RemoveSystemAbility: ABILITY_MGR_SERVICE_ID.");
            break;
        default:
            break;
    }
}

void ReminderEventManager::ReminderNotificationSubscriber::OnCanceled(
    const std::shared_ptr<Notification>& notification,
    const std::shared_ptr<NotificationSortingMap>& sortingMap, int deleteReason)
{
    // Note: Don't modify param notification
    if (deleteReason != NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE) {
        return;
    }
    if (notification == nullptr) {
        return;
    }
    NotificationRequest request = notification->GetNotificationRequest();
    std::string label = request.GetLabel();
    int64_t autoDeletedTime = request.GetAutoDeletedTime();
    if (autoDeletedTime <= 0 || label != ReminderRequest::NOTIFICATION_LABEL) {
        return;
    }

    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    int32_t notificationId = request.GetNotificationId();
    int32_t uid = request.GetOwnerUid() == 0 ? request.GetCreatorUid() : request.GetOwnerUid();
    manager->HandleAutoDeleteReminder(notificationId, uid, autoDeletedTime);
}
}  // namespace OHOS::Notification