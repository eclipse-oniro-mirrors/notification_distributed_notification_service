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

#ifndef ANS_FRAMEWORKS_ETS_ANI_INCLUDE_MANAGER_ANI_GET_NOTIFICATION_PARAMETERS_H
#define ANS_FRAMEWORKS_ETS_ANI_INCLUDE_MANAGER_ANI_GET_NOTIFICATION_PARAMETERS_H

#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"
#include "notification_parameters.h"

namespace OHOS {
namespace NotificationManagerSts {

struct AsyncCallbackInfoNotificationParameters {
    ani_vm *vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    int32_t notificationId = 0;
    std::string label;
    sptr<Notification::NotificationParameters> parameters = nullptr;
};

ani_object AniGetNotificationParameters(ani_env *env, ani_int id, ani_string label);

}  // namespace NotificationManagerSts
}  // namespace OHOS

#endif  // ANS_FRAMEWORKS_ETS_ANI_INCLUDE_MANAGER_ANI_GET_NOTIFICATION_PARAMETERS_H