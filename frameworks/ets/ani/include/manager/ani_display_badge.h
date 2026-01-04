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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISPLAY_BADGE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISPLAY_BADGE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_bundle_option.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
enum BadgeFunction {
    BADGE_NONE,
    IS_BADGE_DISPLAYED,
    GET_BADGE_DISPLAY_STATUS_BY_BUNDLES,
    GET_BADGE_NUMBER,
};

struct AsyncCallbackBadgeInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    BadgeFunction functionType = BADGE_NONE;
    bool isEnable;
    int32_t badgeNumber;
    BundleOption option;
    std::vector<std::pair<Notification::NotificationBundleOption, bool>> options;
    std::vector<Notification::NotificationBundleOption> bundles;
    std::map<sptr<Notification::NotificationBundleOption>, bool> bundleEnable;
};

void HandleBadgeCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable, ani_object callback);
ani_object AniIsBadgeDisplayed(ani_env *env, ani_object obj, ani_object callback);
ani_object AniSetBadgeNumber(ani_env *env, ani_int badgeNumber, ani_object callback);
ani_object AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_int badgeNumber, ani_object callback);
ani_object AniSetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback);
ani_object AniGetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback);
ani_object AniGetBadgeNumber(ani_env *env, ani_object callback);

void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn);
void AniOffBadgeNumberQuery(ani_env *env);
void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num);
}
}
#endif
