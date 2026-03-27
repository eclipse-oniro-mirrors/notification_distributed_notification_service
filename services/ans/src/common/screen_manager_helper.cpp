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

#include "screen_manager_helper.h"

#include "ans_log_wrapper.h"
#include "notification_load_utils.h"
#include <memory>

namespace OHOS {
namespace Notification {
static const std::string DYNAMIC_LIB_PATH = "libans_dynamic.z.so";
static const std::string GET_SCREEN_POWER_FUNC_STR = "ScreenManagerGetScreenPower";

using GET_SCREEN_POWER_FUNC = NotificationScreenPowerState (*)();

std::shared_ptr<ScreenManagerHelper> ScreenManagerHelper::GetInstance()
{
    static std::shared_ptr<ScreenManagerHelper> instance = std::make_shared<ScreenManagerHelper>();
    return instance;
}

NotificationScreenPowerState ScreenManagerHelper::GetScreenPower()
{
    std::unique_ptr<NotificationLoadUtils> loadUtils =
        std::make_unique<NotificationLoadUtils>(DYNAMIC_LIB_PATH);
    if (loadUtils == nullptr || !loadUtils->IsValid()) {
        ANS_LOGW("libans_dynamic not available, return default POWER_OFF");
        return NotificationScreenPowerState::POWER_OFF;
    }
    GET_SCREEN_POWER_FUNC getScreenPowerFunc =
        reinterpret_cast<GET_SCREEN_POWER_FUNC>(loadUtils->GetProxyFunc(GET_SCREEN_POWER_FUNC_STR));
    if (getScreenPowerFunc == nullptr) {
        ANS_LOGW("ScreenManagerGetScreenPower not available, return default POWER_OFF");
        return NotificationScreenPowerState::POWER_OFF;
    }
    return getScreenPowerFunc();
}
}  // namespace Notification
}  // namespace OHOS
