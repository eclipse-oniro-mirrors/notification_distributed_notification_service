/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "system_event_observer.h"

#include "advanced_datashare_helper.h"
#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "notification_preferences.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_clone_manager.h"
#ifdef ALL_SCENARIO_COLLABORATION
#include "distributed_device_manager.h"
#endif
#include "notification_liveview_utils.h"

namespace OHOS {
namespace Notification {
SystemEventObserver::SystemEventObserver(const ISystemEvent &callbacks) : callbacks_(callbacks)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
#endif
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
#endif
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTED);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    commonEventSubscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    subscriber_ = std::make_shared<SystemEventSubscriber>(
        commonEventSubscribeInfo, std::bind(&SystemEventObserver::OnReceiveEvent, this, std::placeholders::_1));

    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

SystemEventObserver::~SystemEventObserver()
{
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
}

sptr<NotificationBundleOption> SystemEventObserver::GetBundleOption(AAFwk::Want want)
{
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    int32_t appIndex = want.GetIntParam("appIndex", -1);
    int32_t uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption.");
        return nullptr;
    }
    bundleOption->SetAppIndex(appIndex);
    return bundleOption;
}

sptr<NotificationBundleOption> SystemEventObserver::GetBundleOptionDataCleared(AAFwk::Want want)
{
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    int32_t appIndex = want.GetIntParam("appIndex", -1);
    // 元能力提供的UID，该UID获取的是want信息中bundleName对应的UID。
    int32_t uid = want.GetIntParam("ohos.aafwk.param.targetUid", -1);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption.");
        return nullptr;
    }
    bundleOption->SetAppIndex(appIndex);
    return bundleOption;
}

void SystemEventObserver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    ANS_LOGD("OnReceiveEvent action is %{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        sptr<NotificationBundleOption> bundleOption = GetBundleOption(want);
        if (bundleOption != nullptr && callbacks_.onBundleRemovedByUserId != nullptr) {
            int32_t userId = data.GetCode();
            callbacks_.onBundleRemovedByUserId(bundleOption, userId);
        }
        if (bundleOption != nullptr) {
            NotificationLiveViewUtils::GetInstance().NotifyLiveViewEvent(action, bundleOption);
            NOTIFICATION_AI_EXTENSION_WRAPPER->NotifyPriorityEvent(action, bundleOption);
        }
        AdvancedNotificationService::GetInstance()->HandleBundleUninstall(bundleOption);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        if (callbacks_.onScreenOn != nullptr) {
            callbacks_.onScreenOn();
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (callbacks_.onScreenOff != nullptr) {
            callbacks_.onScreenOff();
        }
#endif
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        if (userId <= SUBSCRIBE_USER_INIT) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        if (AdvancedNotificationService::GetInstance() == nullptr) {
            ANS_LOGE("new AdvancedNotificationService fail.");
            return;
        }
        NotificationPreferences::GetInstance()->InitSettingFromDisturbDB(userId);
        AdvancedNotificationService::GetInstance()->RecoverLiveViewFromDb(userId);
        NotificationCloneManager::GetInstance().OnUserSwitch(userId);
        DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->OnUserSwitch(userId);
        AdvancedNotificationService::GetInstance()->TriggerLiveViewSwitchCheck(userId);
        AdvancedNotificationService::GetInstance()->RecoverAncoApplicationUserId(userId);
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
        AdvancedNotificationService::GetInstance()->TryStartExtensionSubscribeService();
#endif
#ifdef ALL_SCENARIO_COLLABORATION
        DistributedDeviceManager::GetInstance().InitTrustList();
#endif
        return;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = data.GetCode();
        if (userId <= SUBSCRIBE_USER_INIT) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        if (callbacks_.onResourceRemove != nullptr) {
            callbacks_.onResourceRemove(userId);
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED) {
        int32_t userId = data.GetCode();
        if (userId <= SUBSCRIBE_USER_INIT) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        if (callbacks_.OnUserStopped != nullptr) {
            callbacks_.OnUserStopped(userId);
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        if (callbacks_.onBundleDataCleared != nullptr) {
            sptr<NotificationBundleOption> bundleOption = GetBundleOptionDataCleared(want);
            if (bundleOption != nullptr) {
                callbacks_.onBundleDataCleared(bundleOption);
            }
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START) {
        NotificationCloneManager::GetInstance().OnRestoreStart(want);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON) {
        NotificationPreferences::GetInstance()->SetKioskModeStatus(true);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF) {
        NotificationPreferences::GetInstance()->SetKioskModeStatus(false);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTED) {
        NotificationLiveViewUtils::GetInstance().NotifyLiveViewEvent(action);
    } else {
        OnReceiveEventInner(data);
    }
}

void SystemEventObserver::OnReceiveEventInner(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    sptr<NotificationBundleOption> bundleOption = GetBundleOption(data.GetWant());
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to get bundle option for action: %s", action.c_str());
        return;
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) == 0) {
        OnBundleAddEventInner(data);
        AdvancedNotificationService::GetInstance()->HandleBundleInstall(bundleOption);
        return;
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) == 0) {
        OnBundleUpdateEventInner(data);
        AdvancedNotificationService::GetInstance()->HandleBundleUpdate(bundleOption);
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED) == 0) {
        return OnBootSystemCompletedEventInner(data);
    }
}

void SystemEventObserver::OnBundleAddEventInner(const EventFwk::CommonEventData &data)
{
    sptr<NotificationBundleOption> bundleOption = GetBundleOption(data.GetWant());
    if (bundleOption != nullptr && callbacks_.onBundleAdd != nullptr) {
        callbacks_.onBundleAdd(bundleOption);
    }
    if (bundleOption != nullptr) {
        NotificationLiveViewUtils::GetInstance().NotifyLiveViewEvent(
            EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, bundleOption);
    }
}

void SystemEventObserver::OnBundleUpdateEventInner(const EventFwk::CommonEventData &data)
{
    sptr<NotificationBundleOption> bundleOption = GetBundleOption(data.GetWant());
    if (bundleOption != nullptr && callbacks_.onBundleUpdate != nullptr) {
        callbacks_.onBundleUpdate(bundleOption);
    }

    if (bundleOption != nullptr) {
        NotificationLiveViewUtils::GetInstance().NotifyLiveViewEvent(
            EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, bundleOption);
    }
}

void SystemEventObserver::OnBootSystemCompletedEventInner(const EventFwk::CommonEventData &data)
{
    if (callbacks_.onBootSystemCompleted != nullptr) {
        callbacks_.onBootSystemCompleted();
    }
}
}  // namespace Notification
}  // namespace OHOS
