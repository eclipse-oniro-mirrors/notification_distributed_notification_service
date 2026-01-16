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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_PROFILE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_PROFILE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_disturb_mode.h"
#include "sts_bundle_option.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
enum DistribProfileFunction {
    DISTURB_PROFILE_NONE,
    GET_DO_NOT_DISTURB_PROFILE,
    GET_DO_NOT_DISTURB_PROFILE_BY_USER_ID,
};

struct AsyncCallbackProfileInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    DistribProfileFunction functionType = DISTURB_PROFILE_NONE;
    int64_t notificationId;
    int32_t userId;
    std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> profiles;
    sptr<Notification::NotificationDoNotDisturbProfile> doNotDisturbProfile;
};
void HandleDisturbProfileCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniAddDoNotDisturbProfile(ani_env *env, ani_object obj, ani_object callback);

ani_object AniAddDoNotDisturbProfileByUserId(ani_env *env, ani_object obj, ani_int userId, ani_object callback);

ani_object AniRemoveDoNotDisturbProfile(ani_env *env, ani_object obj, ani_object callback);

ani_object AniRemoveDoNotDisturbProfileByUserId(ani_env *env, ani_object obj, ani_int userId, ani_object callback);

ani_object AniGetDoNotDisturbProfile(ani_env *env, ani_long id, ani_object callback);

ani_object AniGetDoNotDisturbProfileByUserId(ani_env *env, ani_long id, ani_int userId, ani_object callback);
}
}
#endif