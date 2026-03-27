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

#include "ans_dynamic_dependency_interface.h"

#include <cstdint>
#include <string>
#include <vector>

#include "system_sound_dynamic_wrapper.h"
#include "screen_manager_dynamic_wrapper.h"

#define SYMBOL_EXPORT __attribute__ ((visibility("default")))

namespace OHOS {
namespace Notification {
#ifdef __cplusplus
extern "C" {
#endif

SYMBOL_EXPORT bool SystemSoundRemoveCustomizedTone(const std::string uri)
{
    return SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedTone(uri);
}

SYMBOL_EXPORT bool SystemSoundRemoveCustomizedToneList(const std::vector<std::string> uris)
{
    return SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedToneList(uris);
}

SYMBOL_EXPORT NotificationScreenPowerState ScreenManagerGetScreenPower()
{
    return ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
}

#ifdef __cplusplus
}
#endif

}
}
