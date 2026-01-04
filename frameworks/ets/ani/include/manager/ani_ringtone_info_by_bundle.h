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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_RINGTONE_INFO_BY_BUNDLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_RINGTONE_INFO_BY_BUNDLE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_bundle_option.h"
#include "sts_ringtone_info.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
struct AsyncCallbackRingtoneInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    Notification::NotificationBundleOption bundle;
    Notification::NotificationRingtoneInfo ringtoneInfo;
    bool isFuncGetRingtoneInfo = false;
};

void HandleRingtoneFunctionCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniSetRingtoneInfoByBundle(ani_env* env, ani_object bundleObj, ani_object ringtoneInfoObj,
    ani_object callback);

ani_object AniGetRingtoneInfoByBundle(ani_env *env, ani_object bundleObj, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_RINGTONE_INFO_BY_BUNDLE_H