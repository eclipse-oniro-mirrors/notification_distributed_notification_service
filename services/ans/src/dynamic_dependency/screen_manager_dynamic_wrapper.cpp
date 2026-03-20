/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "screen_manager_dynamic_wrapper.h"

#include <memory>
#include <mutex>

#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {

ScreenManagerDynamicWrapper& ScreenManagerDynamicWrapper::GetInstance()
{
    static ScreenManagerDynamicWrapper instance;
    return instance;
}

NotificationScreenPowerState ScreenManagerDynamicWrapper::GetScreenPower()
{
    IPCSkeleton::ResetCallingIdentity();
    Rosen::ScreenPowerState powerState = Rosen::ScreenManager::GetInstance().GetScreenPower();
    ANS_LOGI("GetScreenPower result: %{public}d", static_cast<int32_t>(powerState));

    switch (powerState) {
        case Rosen::ScreenPowerState::POWER_OFF:
            return NotificationScreenPowerState::POWER_OFF;
        case Rosen::ScreenPowerState::POWER_ON:
            return NotificationScreenPowerState::POWER_ON;
        case Rosen::ScreenPowerState::POWER_STAND_BY:
            return NotificationScreenPowerState::POWER_STAND_BY;
        case Rosen::ScreenPowerState::POWER_SUSPEND:
            return NotificationScreenPowerState::POWER_SUSPEND;
        default:
            ANS_LOGW("Unknown screen power state: %{public}d", static_cast<int32_t>(powerState));
            return NotificationScreenPowerState::POWER_OFF;
    }
}
}
}
