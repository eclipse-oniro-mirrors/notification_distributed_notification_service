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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_NOTIFICATION_ENABLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_NOTIFICATION_ENABLE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "notification_disable.h"
#include "sts_bundle_option.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
constexpr int32_t INVALID_USERID = -1;

enum NotificationEnableFunction {
    NOTIFICATION_ENABLED_NONE,
    IS_NOTIFICATION_ENABLED,
    IS_NOTIFICATION_ENABLED_WITH_ID,
    IS_NOTIFICATION_ENABLED_WITH_BUNDLE_OPTION,
    GET_ALL_NOTIFICATION_ENABLED_BUNDLES,
    GET_ALL_NOTIFICATION_ENABLED_BUNDLES_BY_USER_ID,
    GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
};


struct AsyncCallbackEnabledInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    NotificationEnableFunction functionType = NOTIFICATION_ENABLED_NONE;
    bool isAllowed = false;
    int32_t userId;
    BundleOption notificationOption;
    Notification::NotificationDisable param;
    std::vector<BundleOption> bundleOptions;
};

void HandleNotificationEnabledCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniIsNotificationEnabled(ani_env *env, ani_object callback);
ani_object AniIsNotificationEnabledWithId(ani_env *env, ani_int userId, ani_object callback);
ani_object AniIsNotificationEnabledWithBundleOption(ani_env *env, ani_object bundleOption, ani_object callback);
ani_object AniSetNotificationEnable(ani_env *env, ani_object bundleOption, ani_boolean enable, ani_object callback);
ani_object AniSetSyncNotificationEnabledWithoutApp(ani_env *env, ani_int userId, ani_boolean enabled,
    ani_object callback);
ani_object AniGetAllNotificationEnabledBundles(ani_env *env, ani_object callback);
ani_object AniGetAllNotificationEnabledBundlesByUserId(ani_env *env, ani_int userId, ani_object callback);
ani_boolean AniIsNotificationEnabledSync(ani_env *env);
ani_object AniGetSyncNotificationEnabledWithoutApp(ani_env *env, ani_int userId, ani_object callback);
ani_object AniDisableNotificationFeature(ani_env *env, ani_boolean disabled, ani_object bundleList,
    ani_object callback);
ani_object AniDisableNotificationFeatureWithId(ani_env *env, ani_boolean disabled, ani_object bundleList,
    ani_int userId, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif

