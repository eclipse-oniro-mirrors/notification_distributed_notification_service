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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_PRIORITY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_PRIORITY_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"
#include "sts_bundle_option.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"

namespace OHOS {
namespace NotificationManagerSts {

enum PriorityFunction {
    PRIORITY_NONE,
    GET_BUNDLE_PRIORITY_CONFIG,
    IS_PRIORITY_ENABLED_BY_BUNDLE,
    IS_PRIORITY_ENABLED,
};

struct AsyncCallbackPriorityInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    PriorityFunction functionType = PRIORITY_NONE;
    std::string valueStr;
    Notification::NotificationBundleOption option;
    OHOS::Notification::NotificationConstant::PriorityEnableStatus status =
        OHOS::Notification::NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    bool isPriorityEnabled;
};

void HandlePriorityFunctionCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniSetBundlePriorityConfig(ani_env* env,
    ani_object obj, ani_string value, ani_object callback);
ani_object AniGetBundlePriorityConfig(ani_env* env, ani_object obj, ani_object callback);
ani_object AniSetPriorityEnabledByBundle(ani_env* env,
    ani_object obj, ani_enum_item enableStatus, ani_object callback);
ani_object AniIsPriorityEnabledByBundle(ani_env* env, ani_object obj, ani_object callback);
ani_object AniSetPriorityEnabled(ani_env* env, ani_boolean enable, ani_object callback);
ani_object AniIsPriorityEnabled(ani_env* env, ani_object callback);
void AniSetPriorityEnabledByBundles(ani_env *env, ani_object obj);
ani_object AniGetPriorityEnabledByBundles(ani_env *env, ani_object obj);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_PRIORITY_H