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

#include "screenlock_manager.h"
#include "distributed_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"

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
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        DistributedService::GetInstance().SyncDeviceState(SCREEN_OFF);
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        DistributedService::GetInstance().SyncDeviceState(SCREEN_ON);
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        if (userId <= SUBSCRIBE_USER_INIT) {
            ANS_LOGE("Illegal userId, userId[%{public}d].", userId);
            return;
        }
        DistributedService::GetInstance().SetCurrentUserId(userId);
        return;
    }
}

OberverService& OberverService::GetInstance()
{
    static OberverService oberverService;
    return oberverService;
}

void OberverService::Init(uint16_t deviceType)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    if (deviceType != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<DistributedEventSubscriber>(subscribeInfo);
    if (subscriber_ == nullptr) {
        ANS_LOGE("subscriber_ is nullptr");
        return;
    }
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    ANS_LOGI("ScreenLock service successfully.");
}

int32_t OberverService::IsScreenLocked()
{
    bool state = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
    return state ? SCREEN_OFF : SCREEN_ON;
}

}
}
