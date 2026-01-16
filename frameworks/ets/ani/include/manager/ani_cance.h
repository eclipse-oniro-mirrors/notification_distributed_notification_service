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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_CANCEL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_CANCEL_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "notification_bundle_option.h"
#include "sts_bundle_option.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {

struct AsyncCallbackCancelInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    int32_t notificationId;
    std::string labelStr;
    BundleOption bundleOption;
    int32_t convertedId;
    int32_t userId;
    std::string bundleStr;
    std::string groupNameStr;
};

void HandleCancelCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniCancelAll(ani_env *env, ani_object callback);
ani_object AniCancelWithId(ani_env *env, ani_int id, ani_object callback);
ani_object AniCancelWithIdLabel(ani_env *env, ani_int id, ani_string label, ani_object callback);
ani_object AniCancelWithBundle(ani_env *env, ani_object bundleObj, ani_int id, ani_object callback);
ani_object AniCancelAsBundle(ani_env *env, ani_int id, ani_string representativeBundle,
    ani_int userId, ani_object callback);
ani_object AniCancelAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle,
    ani_int userId, ani_object callback);
ani_object AniCancelGroup(ani_env *env, ani_string groupName, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif