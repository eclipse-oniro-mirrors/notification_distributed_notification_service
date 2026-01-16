/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_DATA_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_bundle_option.h"
#include "notification_do_not_disturb_date.h"
#include "sts_notification_manager.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {

enum DistribDataFunction {
    DISTURB_DATA_NONE,
    GET_DO_NOT_DISTURB_DATE,
    GET_DO_NOT_DISTURB_DATE_WITH_ID,
    IS_SUPPORT_DO_NOT_DISTURB_DATE_MODE,
};

struct AsyncCallbackDisturbInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    DistribDataFunction functionType = DISTURB_DATA_NONE;
    int32_t userId;
    Notification::NotificationDoNotDisturbDate doNotDisturbDate;
    bool isSupportDoNotDisturbMode = false;
};

void HandleDoDisturbDataCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniSetDoNotDisturbDate(ani_env *env, ani_object date, ani_object callback);
ani_object AniSetDoNotDisturbDateWithId(ani_env *env, ani_object date, ani_int userId, ani_object callback);
ani_object AniGetDoNotDisturbDate(ani_env *env, ani_object callback);
ani_object AniGetDoNotDisturbDateWithId(ani_env *env, ani_int userId, ani_object callback);
ani_object AniIsSupportDoNotDisturbMode(ani_env *env, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif