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
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    commonEventSubscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    subscriber_ = std::make_shared<SystemEventSubscriber>(
        commonEventSubscribeInfo, std::bind(&SystemEventObserver::OnReceiveEvent, this, std::placeholders::_1));

    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    InitEventList();
}

SystemEventObserver::~SystemEventObserver()
{
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
}

sptr<NotificationBundleOption> SystemEventObserver::GetBundleOption(AAFwk::Want want)
{
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    int32_t uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
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
        NotificationPreferences::GetInstance().InitSettingFromDisturbDB();
        AdvancedNotificationService::GetInstance()->RecoverLiveViewFromDb();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = data.GetCode();
        if (userId <= DEFAULT_USER_ID) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        if (callbacks_.onResourceRemove != nullptr) {
            callbacks_.onResourceRemove(userId);
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        if (callbacks_.onBundleDataCleared != nullptr) {
            sptr<NotificationBundleOption> bundleOption = GetBundleOption(want);
            if (bundleOption != nullptr) {
                callbacks_.onBundleDataCleared(bundleOption);
            }
        }
    } else {
        OnReceiveEventInner(data);
    }
}

void SystemEventObserver::InitEventList()
{
    memberFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED] =
        &SystemEventObserver::OnBundleAddEventInner;
    memberFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED] =
        &SystemEventObserver::OnBundleUpdateEventInner;
    memberFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED] =
        &SystemEventObserver::OnBootSystemCompletedEventInner;
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    memberFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED] =
        &SystemEventObserver::OnScreenLock;
    memberFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED] =
        &SystemEventObserver::OnScreenUnlock;
#endif
}

void SystemEventObserver::OnReceiveEventInner(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    auto itFunc = memberFuncMap_.find(action);
    if (itFunc == memberFuncMap_.end()) {
        ANS_LOGE("Action %{public}s callback is not found.", action.c_str());
        return;
    }

    if (itFunc->second == nullptr) {
        ANS_LOGE("Action [%{public}s] callback is nullptr.", action.c_str());
        return;
    }

    (this->*(itFunc->second))(data);
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
void SystemEventObserver::OnScreenLock(const EventFwk::CommonEventData &data)
{
    if (callbacks_.onScreenLock != nullptr) {
        callbacks_.onScreenLock();
    }
}

void SystemEventObserver::OnScreenUnlock(const EventFwk::CommonEventData &data)
{
    if (callbacks_.onScreenUnlock != nullptr) {
        callbacks_.onScreenUnlock();
    }
}
#endif
}  // namespace Notification
}  // namespace OHOS
