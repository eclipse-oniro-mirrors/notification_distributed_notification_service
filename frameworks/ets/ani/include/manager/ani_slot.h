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
#include "concurrency_helpers.h"
#include "notification_bundle_option.h"
#include "notification_slot.h"
#include "sts_callback_promise.h"

namespace OHOS {
namespace NotificationManagerSts {
using BundleOption = OHOS::Notification::NotificationBundleOption;

enum SlotFunction {
    SLOT_NONE,
    GET_SLOT_FLAGS_BY_BUNDLE,
    GET_SLOTS_BY_BUNDLE,
    IS_NOTIFICATION_SLOT_ENABLED,
    GET_SLOT,
    GET_SLOTS,
    GET_SLOT_BY_BUNDLE,
    GET_SLOT_NUM_BY_BUNDLE,
    GET_NOTIFICATION_SETTING,
};

struct EnableSlotParameter {
    bool isEnabled = false;
    bool isForceControl = false;
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    Notification::NotificationSlot slot;
    std::vector<Notification::NotificationSlot> slots;
};

struct AsyncCallbackSlotInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    SlotFunction functionType = SLOT_NONE;
    EnableSlotParameter param;
    std::vector<sptr<Notification::NotificationSlot>> slots;
    sptr<Notification::NotificationSlot> slot;
    uint64_t slotNum = 0;
    uint32_t slotFlags = 0;
};

void HandleSlotFunctionCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);
void HandleSlotFunctionCallbackComplete1(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniGetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_object callback);
ani_object AniSetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_long slotFlags, ani_object callback);
ani_object AniGetSlotsByBundle(ani_env *env, ani_object bundleOption, ani_object callback);
ani_object AniIsNotificationSlotEnabled(ani_env *env, ani_object bundleOption, ani_enum_item type,
    ani_object callback);
ani_object AniSetNotificationEnableSlot(ani_env *env, ani_object bundleOption, ani_enum_item  type,
    ani_boolean enable, ani_object callback);
ani_object AniSetNotificationEnableSlotWithForce(ani_env *env, ani_object parameterObj, ani_object callback);
ani_object AniAddSlotByNotificationSlot(ani_env *env, ani_object notificationSlotObj, ani_object callback);
ani_object AniAddSlotBySlotType(ani_env *env, ani_enum_item enumObj, ani_object callback);
ani_object AniAddSlots(ani_env *env, ani_object notificationSlotArrayObj, ani_object callback);
ani_object AniGetSlot(ani_env *env, ani_enum_item enumObj, ani_object callback);
ani_object AniGetSlots(ani_env *env, ani_object callback);
ani_object AniGetSlotByBundle(ani_env *env, ani_object bundleOption, ani_enum_item type, ani_object callback);
ani_object AniRemoveSlot(ani_env *env, ani_enum_item enumObj, ani_object callback);
ani_object AniRemoveAllSlots(ani_env *env, ani_object callback);
ani_object AniSetSlotByBundle(ani_env *env, ani_object bundleOptionObj, ani_object slotObj, ani_object callback);
ani_object AniGetSlotNumByBundle(ani_env *env, ani_object bundleOption, ani_object callback);
ani_object AniGetNotificationSetting(ani_env *env, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif

