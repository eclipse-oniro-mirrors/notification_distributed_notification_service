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

namespace OHOS {
namespace NotificationManagerSts {
const int32_t DISTURB_DEFAULT_FLAG = 13;

ani_boolean AniIsDistributedEnabled(ani_env* env);
ani_boolean AniIsDistributedEnabledByBundle(ani_env* env, ani_object obj);
ani_boolean AniIsDistributedEnabledByBundleType(ani_env* env, ani_object obj, ani_string deviceType);
void AniSetDistributedEnable(ani_env* env, ani_boolean enabled);
void AniSetDistributedEnableByBundle(ani_env *env, ani_object obj, ani_boolean enable);
void AniSetDistributedEnableByBundleAndType(ani_env *env, ani_object obj, ani_string deviceType, ani_boolean enable);
void AniSetTargetDeviceStatus(ani_env* env, ani_string deviceType, ani_long status);
ani_boolean AniIsSmartReminderEnabled(ani_env *env, ani_string deviceType);
void AniSetSmartReminderEnable(ani_env *env, ani_string deviceType, ani_boolean enable);
void AniSetDistributedEnableBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType, ani_boolean enable);
ani_boolean AniIsDistributedEnabledBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif