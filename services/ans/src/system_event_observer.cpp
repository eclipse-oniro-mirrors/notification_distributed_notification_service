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

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "notification_preferences.h"
#include "notification_clone_manager.h"

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
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
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
    bundleOption->SetAppIndex(appIndex);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption.");
        return nullptr;
    }
    return bundleOption;
}

sptr<NotificationBundleOption> SystemEventObserver::GetBundleOptionDataCleared(AAFwk::Want want)
{
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    int32_t appIndex = want.GetIntParam("appIndex", -1);
    int32_t uid = want.GetIntParam("ohos.aafwk.param.targetUid", -1);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    bundleOption->SetAppIndex(appIndex);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption.");
        return nullptr;
    }
    return bundleOption;
}

void SystemEventObserver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    ANS_LOGD("OnReceiveEvent action is %{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        if (callbacks_.onBundleRemoved != nullptr) {
            sptr<NotificationBundleOption> bundleOption = GetBundleOption(want);
            if (bundleOption != nullptr) {
                callbacks_.onBundleRemoved(bundleOption);
            }
        }
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
        NotificationPreferences::GetInstance()->InitSettingFromDisturbDB(userId);
        AdvancedNotificationService::GetInstance()->RecoverLiveViewFromDb(userId);
        NotificationCloneManager::GetInstance().OnUserSwitch(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = data.GetCode();
        if (userId <= SUBSCRIBE_USER_INIT) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        if (callbacks_.onResourceRemove != nullptr) {
            callbacks_.onResourceRemove(userId);
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
    } else {
        OnReceiveEventInner(data);
    }
}

void SystemEventObserver::OnReceiveEventInner(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) == 0) {
        return OnBundleAddEventInner(data);
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) == 0) {
        return OnBundleUpdateEventInner(data);
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED) == 0) {
        return OnBootSystemCompletedEventInner(data);
    }
}

void SystemEventObserver::OnBundleAddEventInner(const EventFwk::CommonEventData &data)
{
    if (callbacks_.onBundleAdd != nullptr) {
        sptr<NotificationBundleOption> bundleOption = GetBundleOption(data.GetWant());
        if (bundleOption != nullptr) {
            callbacks_.onBundleAdd(bundleOption);
        }
    }
}

void SystemEventObserver::OnBundleUpdateEventInner(const EventFwk::CommonEventData &data)
{
    if (callbacks_.onBundleUpdate != nullptr) {
        sptr<NotificationBundleOption> bundleOption = GetBundleOption(data.GetWant());
        if (bundleOption != nullptr) {
            callbacks_.onBundleUpdate(bundleOption);
        }
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
