/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "distributed_observer_service.h"

#include "distributed_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "distributed_operation_helper.h"

namespace OHOS {
namespace Notification {

namespace {
const static int32_t SCREEN_OFF = 0;
const static int32_t SCREEN_ON = 1;
}

void DistributedEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto const &want = data.GetWant();
    std::string action = want.GetAction();
    ANS_LOGI("DistributedEventSubscriber receiver event %{public}s", action.c_str());
#ifdef DISTRIBUTED_FEATURE_MASTER
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        OperationService::GetInstance().HandleScreenEvent();
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        OHOS::AppExecFwk::ElementName ele = want.GetElement();
        std::string bundleName = ele.GetBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("Illegal bundle name.");
            return;
        }
        DistributedService::GetInstance().HandleBundlesEvent(bundleName, action);
        return;
    }
#else
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        DistributedService::GetInstance().SyncDeviceStatus(SCREEN_OFF);
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        DistributedService::GetInstance().SyncDeviceStatus(SCREEN_ON);
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        OHOS::AppExecFwk::ElementName ele = want.GetElement();
        std::string bundleName = ele.GetBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("Illegal bundle name.");
            return;
        }
        bool isAddBundle =
            (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) ? true : false;
        DistributedService::GetInstance().SyncInstalledBundle(bundleName, isAddBundle);
        return;
    }
#endif
}

OberverService& OberverService::GetInstance()
{
    static OberverService oberverService;
    return oberverService;
}

void OberverService::Init(uint16_t deviceType)
{
    EventFwk::MatchingSkills matchingSkills;
#ifdef DISTRIBUTED_FEATURE_MASTER
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
#else
    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD ||
        deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1 ||
        deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_PC) {
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    }
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
#endif
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<DistributedEventSubscriber>(subscribeInfo);
    if (subscriber_ == nullptr) {
        ANS_LOGE("subscriber_ is nullptr");
        return;
    }
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    ANS_LOGI("OberverService service successfully.");
}

int32_t OberverService::IsScreenLocked()
{
    bool state = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
    return state ? SCREEN_OFF : SCREEN_ON;
}

void OberverService::Destory()
{
    EventFwk::CommonEventManager::NewUnSubscribeCommonEventSync(subscriber_);
    ANS_LOGI("OberverService service destory.");
}

int32_t OberverService::Unlock(
    const ScreenLock::Action &action, const sptr<ScreenLock::ScreenLockCallbackInterface> &listener)
{
    return ScreenLock::ScreenLockManager::GetInstance()->Unlock(action, listener);
}
}
}
