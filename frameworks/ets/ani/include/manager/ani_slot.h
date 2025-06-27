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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_SLOT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_SLOT_H
#include "ani.h"

namespace OHOS {
namespace NotificationManagerSts {
ani_int AniGetSlotFlagsByBundle(ani_env *env, ani_object obj);
void AniSetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_double slotFlags);

ani_object AniGetSlotsByBundle(ani_env *env, ani_object bundleOption);
ani_boolean AniIsNotificationSlotEnabled(ani_env *env, ani_object bundleOption, ani_enum_item  type);
void AniSetNotificationEnableSlot(ani_env *env, ani_object bundleOption, ani_enum_item  type, ani_boolean enable);
void AniSetNotificationEnableSlotWithForce(ani_env *env, ani_object bundleOption, ani_enum_item  type,
    ani_boolean enable, ani_boolean isForceControl);
void AniAddSlotByNotificationSlot(ani_env *env, ani_object notificationSlotObj);
void AniAddSlotBySlotType(ani_env *env, ani_enum_item enumObj);
void AniAddSlots(ani_env *env, ani_object notificationSlotArrayObj);
ani_object AniGetSlot(ani_env *env, ani_enum_item enumObj);
ani_object AniGetSlots(ani_env *env);
ani_object AniGetSlotByBundle(ani_env *env, ani_object bundleOption, ani_enum_item  type);
void AniRemoveSlot(ani_env *env, ani_enum_item enumObj);
void AniRemoveAllSlots(ani_env *env);
void AniSetSlotByBundle(ani_env *env, ani_object bundleOptionObj, ani_object slotObj);
ani_double AniGetSlotNumByBundle(ani_env *env, ani_object bundleOption);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif

