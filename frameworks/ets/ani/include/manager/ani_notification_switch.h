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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_NOTIFICATION_SWITCH_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_NOTIFICATION_SWITCH_H

#include <cstdint>
#include <string>

#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
enum NotificationSwitchFunctionType {
    NOTIFICATION_SWITCH_FUNCTION_NONE = 0,
    GET_NOTIFICATION_SWITCH,
};

struct AsyncCallbackNotificationSwitchInfo {
    ani_vm *vm = nullptr;
    arkts::concurrency_helpers::AsyncWork *asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    NotificationSwitchFunctionType functionType =
        NOTIFICATION_SWITCH_FUNCTION_NONE;
    std::string switchName;
    bool switchState = false;
    int32_t userId = 0;
    int32_t enableStatus = 0;
};

void HandleNotificationSwitchCallbackComplete(ani_env *env,
    arkts::concurrency_helpers::WorkStatus status, void *data);

ani_object AniSetNotificationSwitch(ani_env *env, ani_string switchName, ani_boolean switchState, ani_int userId);
ani_object AniGetNotificationSwitch(ani_env *env, ani_string switchName, ani_int userId);
} // namespace NotificationManagerSts
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_NOTIFICATION_SWITCH_H