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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_SLOT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_SLOT_H
#include "ani.h"
#include "notification_constant.h"
#include "notification_slot.h"

namespace OHOS {
namespace NotificationSts {
using SlotType = OHOS::Notification::NotificationConstant::SlotType;
using SlotLevel = OHOS::Notification::NotificationSlot::NotificationLevel;
using NotificationSlot = OHOS::Notification::NotificationSlot;

constexpr const char* NOTIFICATION_SOLT_CLASSNAME = "Lnotification/notificationSlot/NotificationSlotInner;";
bool SetOptionalFieldSlotType(ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName,
    const SlotType value);
bool SetOptionalFieldSlotLevel(ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName,
    const SlotLevel value);
bool WrapNotificationSlot(ani_env *env, sptr<NotificationSlot> slot, ani_object &outAniObj);
bool WrapNotificationSlotArray(ani_env *env, const std::vector<sptr<NotificationSlot>>& slots,
    ani_object &outAniObj);

} // namespace NotificationSts
} // OHOS
#endif