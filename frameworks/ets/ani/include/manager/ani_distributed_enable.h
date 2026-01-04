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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISTRIBUTED_ENBLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISTRIBUTED_ENBLE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "notification_constant.h"
#include "sts_bundle_option.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {

const int32_t DISTURB_DEFAULT_FLAG = 13;

enum DistribFunction {
    DISTURB_NONE,
    IS_DISTURB_ENABLED,
    IS_DISTURB_ENABLED_BY_BUNDLE,
    IS_DISTURB_ENABLED_BY_BUNDLE_TYPE,
    IS_DISTURB_ENABLED_BY_SLOT,
    IS_DISTURB_ENABLED_BY_DEVICE_TYPE,
    GET_DISTURB_ENABLED_DEVICE_LIST,
    IS_SMART_REMINDER_ENABLE,
};

struct AsyncCallbackDistributedInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    DistribFunction functionType = DISTURB_NONE;
    bool isEnabled = false;
    std::string deviceTypeStr;
    int32_t status;
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType =
        Notification::NotificationConstant::SlotType::OTHER;
    std::vector<DistributedBundleOption> bundles;
    std::vector<std::string> deviceList;
};
void HandleDistribCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniIsDistributedEnabled(ani_env* env, ani_object callback);
ani_object AniIsDistributedEnabledByBundle(ani_env* env, ani_object obj, ani_object callback);
ani_object AniIsDistributedEnabledByBundleType(ani_env* env, ani_object obj, ani_string deviceType,
    ani_object callback);
ani_object AniSetDistributedEnable(ani_env* env, ani_boolean enabled, ani_object callback);
ani_object AniSetDistributedEnableByBundle(ani_env* env, ani_object obj, ani_boolean enabled, ani_object callback);
ani_object AniSetDistributedEnableByBundleAndType(ani_env* env, ani_object obj, ani_string deviceType,
    ani_boolean enabled, ani_object callback);
ani_object AniSetDistributedEnableBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType,
    ani_boolean enable, ani_object callback);
ani_object AniIsDistributedEnabledBySlot(ani_env* env,
    ani_enum_item slot, ani_string deviceType, ani_object callback);
ani_object AniIsDistributedEnabledByDeviceType(ani_env* env, ani_string deviceType, ani_object callback);
ani_object AniSetDistributedEnabledByDeviceType(ani_env* env,
    ani_boolean enable, ani_string deviceType, ani_object callback);
ani_object AniSetDistributedEnableByBundles(ani_env* env, ani_object obj, ani_string deviceType, ani_object callback);
ani_object AniGetDistributedDeviceList(ani_env* env, ani_object callback);
ani_object AniSetTargetDeviceStatus(ani_env* env, ani_string deviceType, ani_long status, ani_object callback);
ani_object AniIsSmartReminderEnabled(ani_env* env, ani_string deviceType, ani_object callback);
ani_object AniSetSmartReminderEnable(ani_env* env, ani_string deviceType, ani_boolean enable, ani_object callback);

} // namespace NotificationManagerSts
} // namespace OHOS
#endif