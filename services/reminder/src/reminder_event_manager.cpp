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

#include "reminder_event_manager.h"

#include "ans_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "reminder_bundle_manager_helper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "notification_helper.h"
#include "string_ex.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Notification {
static const std::string NOTIFICATION_LABEL = "REMINDER_AGENT";
static constexpr const char* UNLOCK_SCREEN_EVENT = "common.event.UNLOCK_SCREEN";
std::shared_ptr<ReminderEventManager::ReminderNotificationSubscriber> ReminderEventManager::subscriber_
    = nullptr;

ReminderEventManager::ReminderEventManager(std::shared_ptr<ReminderDataManager> &reminderDataManager)
{
    init(reminderDataManager);
}

void ReminderEventManager::init(std::shared_ptr<ReminderDataManager> &reminderDataManager) const
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
    auto customSubscriber = std::make_shared<ReminderEventCustomSubscriber>(customSubscriberInfo, reminderDataManager);

    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto subscriber = std::make_shared<ReminderEventSubscriber>(subscriberInfo, reminderDataManager);

    MatchingSkills screenMatchingSkills;
    screenMatchingSkills.AddEvent(UNLOCK_SCREEN_EVENT);
    CommonEventSubscribeInfo screenSubscriberInfo(screenMatchingSkills);
    screenSubscriberInfo.SetPublisherBundleName(AppExecFwk::Constants::SCENE_BOARD_BUNDLE_NAME);
    auto screenSubscriber = std::make_shared<ReminderEventSubscriber>(screenSubscriberInfo, reminderDataManager);

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (CommonEventManager::SubscribeCommonEvent(subscriber) &&
        CommonEventManager::SubscribeCommonEvent(customSubscriber) &&
        CommonEventManager::SubscribeCommonEvent(screenSubscriber)) {
        ANSR_LOGD("SubscribeCommonEvent ok");
    } else {
        ANSR_LOGD("SubscribeCommonEvent fail");
    }
    IPCSkeleton::SetCallingIdentity(identity);

    subscriber_ = std::make_shared<ReminderNotificationSubscriber>(reminderDataManager);
    if (NotificationHelper::SubscribeNotification(*subscriber_) != ERR_OK) {
        ANSR_LOGD("SubscribeNotification failed");
    }

    SubscribeSystemAbility(reminderDataManager);
}

void ReminderEventManager::SubscribeSystemAbility(std::shared_ptr<ReminderDataManager> &reminderDataManager) const
{
    sptr<SystemAbilityStatusChangeListener> statusChangeListener
        = new (std::nothrow) SystemAbilityStatusChangeListener(reminderDataManager);
    if (statusChangeListener == nullptr) {
        ANSR_LOGE("Failed to create statusChangeListener due to no memory.");
        return;
    }
    // app mgr
    sptr<SystemAbilityStatusChangeListener> appMgrStatusChangeListener
        = new (std::nothrow) SystemAbilityStatusChangeListener(reminderDataManager);
    if (appMgrStatusChangeListener == nullptr) {
        ANSR_LOGE("Failed to create appMgrStatusChangeListener due to no memory.");
        return;
    }
    // ability mgr
    sptr<SystemAbilityStatusChangeListener> abilityMgrStatusListener
        = new (std::nothrow) SystemAbilityStatusChangeListener(reminderDataManager);
    if (abilityMgrStatusListener == nullptr) {
        ANSR_LOGE("Failed to create abilityMgrStatusListener due to no memory.");
        return;
    }

    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        ANSR_LOGD("samgrProxy is null");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, statusChangeListener);
    if (ret != ERR_OK) {
        ANSR_LOGE("subscribe system ability id: %{public}d failed", BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    }
    ret = samgrProxy->SubscribeSystemAbility(APP_MGR_SERVICE_ID, appMgrStatusChangeListener);
    if (ret != ERR_OK) {
        ANSR_LOGE("subscribe system ability id: %{public}d failed", APP_MGR_SERVICE_ID);
    }
    ret = samgrProxy->SubscribeSystemAbility(ABILITY_MGR_SERVICE_ID, abilityMgrStatusListener);
    if (ret != ERR_OK) {
        ANSR_LOGE("subscribe system ability id: %{public}d failed", ABILITY_MGR_SERVICE_ID);
    }
}

ReminderEventManager::ReminderEventSubscriber::ReminderEventSubscriber(
    const CommonEventSubscribeInfo &subscriberInfo,
    std::shared_ptr<ReminderDataManager> &reminderDataManager) : CommonEventSubscriber(subscriberInfo)
{
    reminderDataManager_ = reminderDataManager;
}

ReminderEventManager::ReminderEventCustomSubscriber::ReminderEventCustomSubscriber(
    const CommonEventSubscribeInfo &subscriberInfo,
    std::shared_ptr<ReminderDataManager> &reminderDataManager) : CommonEventSubscriber(subscriberInfo)
{
    reminderDataManager_ = reminderDataManager;
}

void ReminderEventManager::ReminderEventCustomSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    Want want = data.GetWant();
    std::string action = want.GetAction();
    ANSR_LOGI("Recieved common event:%{public}s", action.c_str());
    if (action == ReminderRequest::REMINDER_EVENT_ALARM_ALERT) {
        reminderDataManager_->ShowActiveReminder(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT) {
        reminderDataManager_->TerminateAlerting(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CLOSE_ALERT) {
        reminderDataManager_->CloseReminder(want, true);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT) {
        reminderDataManager_->SnoozeReminder(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT) {
        reminderDataManager_->HandleCustomButtonClick(want);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION) {
        reminderDataManager_->CloseReminder(want, false, false);
        return;
    }
    if (action == ReminderRequest::REMINDER_EVENT_CLICK_ALERT) {
        reminderDataManager_->ClickReminder(want);
        return;
    }
}

void ReminderEventManager::ReminderEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    Want want = data.GetWant();
    std::string action = want.GetAction();
    ANSR_LOGD("Recieved common event:%{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        HandlePackageRemove(want);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        HandlePackageRemove(want);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_RESTARTED) {
        HandleProcessDied(want);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED) {
        reminderDataManager_->RefreshRemindersDueToSysTimeChange(ReminderDataManager::TIME_ZONE_CHANGE);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_TIME_CHANGED) {
        reminderDataManager_->RefreshRemindersDueToSysTimeChange(ReminderDataManager::DATE_TIME_CHANGE);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        reminderDataManager_->OnUserSwitch(data.GetCode());
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        reminderDataManager_->OnUserRemove(data.GetCode());
        return;
    }
    if (action.compare(UNLOCK_SCREEN_EVENT) == 0) {
        reminderDataManager_->OnUnlockScreen();
    }
}

void ReminderEventManager::ReminderEventSubscriber::HandlePackageRemove(const EventFwk::Want &want) const
{
    OHOS::AppExecFwk::ElementName ele = want.GetElement();
    std::string bundleName = ele.GetBundleName();
    int32_t userId = want.GetIntParam(OHOS::AppExecFwk::Constants::USER_ID, -1);
    int32_t uid = want.GetIntParam(OHOS::AppExecFwk::Constants::UID, -1);
    reminderDataManager_->CancelAllReminders(bundleName, userId, uid);
}

void ReminderEventManager::ReminderEventSubscriber::HandleProcessDied(const EventFwk::Want &want) const
{
    int32_t uid = GetUid(want);
    reminderDataManager_->OnProcessDiedLocked(uid);
}

int32_t ReminderEventManager::ReminderEventSubscriber::GetUid(
    const OHOS::EventFwk::Want &want) const
{
    OHOS::AppExecFwk::ElementName ele = want.GetElement();
    std::string bundleName = ele.GetBundleName();
    int32_t userId = want.GetIntParam(OHOS::AppExecFwk::Constants::USER_ID, -1);
    int32_t uid = ReminderBundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId);
    ANSR_LOGD("bundleName=%{public}s, userId=%{private}d, uid=%{public}d", bundleName.c_str(), userId, uid);
    return uid;
}

ReminderEventManager::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<ReminderDataManager> &reminderDataManager)
{
    reminderDataManager_ = reminderDataManager;
}

void ReminderEventManager::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    ANSR_LOGD("OnAddSystemAbilityInner");
    switch (systemAbilityId) {
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID:
            ANSR_LOGD("OnAddSystemAbilityInner: BUNDLE_MGR_SERVICE_SYS_ABILITY");
            reminderDataManager_->OnBundleMgrServiceStart();
            break;
        case APP_MGR_SERVICE_ID:
            ANSR_LOGD("OnAddSystemAbilityInner: APP_MGR_SERVICE");
            break;
        case ABILITY_MGR_SERVICE_ID:
            ANSR_LOGD("OnAddSystemAbilityInner ABILITY_MGR_SERVICE_ID");
            reminderDataManager_->OnAbilityMgrServiceStart();
            break;
        default:
            break;
    }
}

void ReminderEventManager::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    ANSR_LOGD("OnRemoveSystemAbilityInner");
    switch (systemAbilityId) {
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID:
            ANSR_LOGD("OnRemoveSystemAbilityInner: BUNDLE_MGR_SERVICE_SYS_ABILITY");
            break;
        case APP_MGR_SERVICE_ID:
            ANSR_LOGD("OnRemoveSystemAbilityInner: APP_MGR_SERVICE");
            reminderDataManager_->OnRemoveAppMgr();
            break;
        case ABILITY_MGR_SERVICE_ID:
            ANSR_LOGD("OnRemoveSystemAbilityInner ABILITY_MGR_SERVICE_ID");
            break;
        default:
            break;
    }
}

ReminderEventManager::ReminderNotificationSubscriber::ReminderNotificationSubscriber(
    std::shared_ptr<ReminderDataManager> &reminderDataManager)
{
    reminderDataManager_ = reminderDataManager;
}

ReminderEventManager::ReminderNotificationSubscriber::~ReminderNotificationSubscriber() {}

void ReminderEventManager::ReminderNotificationSubscriber::OnConnected() {}

void ReminderEventManager::ReminderNotificationSubscriber::OnDisconnected() {}

void ReminderEventManager::ReminderNotificationSubscriber::OnCanceled(
    const std::shared_ptr<Notification> &notification,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason)
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
    if (autoDeletedTime <= 0 || label != NOTIFICATION_LABEL) {
        return;
    }

    if (reminderDataManager_ == nullptr) {
        return;
    }
    int32_t notificationId = request.GetNotificationId();
    int32_t uid = request.GetOwnerUid() == 0 ? request.GetCreatorUid() : request.GetOwnerUid();
    reminderDataManager_->HandleAutoDeleteReminder(notificationId, uid, autoDeletedTime);
}

void ReminderEventManager::ReminderNotificationSubscriber::OnConsumed(const std::shared_ptr<Notification> &notification,
    const std::shared_ptr<NotificationSortingMap> &sortingMap) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnUpdate(
    const std::shared_ptr<NotificationSortingMap> &sortingMap) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnDied() {}

void ReminderEventManager::ReminderNotificationSubscriber::OnDoNotDisturbDateChange(
    const std::shared_ptr<NotificationDoNotDisturbDate> &date) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnBadgeChanged(
    const std::shared_ptr<BadgeNumberCallbackData> &badgeData) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData) {}

void ReminderEventManager::ReminderNotificationSubscriber::OnBatchCanceled(
    const std::vector<std::shared_ptr<Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) {}
}  // namespace OHOS
}  // namespace Notification
