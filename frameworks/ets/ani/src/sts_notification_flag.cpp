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
#include "sts_notification_flag.h"

#include "sts_common.h"

namespace OHOS {
namespace NotificationSts {
bool WarpNotificationFlags(ani_env* env, const std::shared_ptr<NotificationFlags> &flags,
    ani_object &flagsObject)
{
    if (flags == nullptr) {
        ANS_LOGE("flags is null");
        return false;
    }

    ani_class flagsCls = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationFlags/NotificationFlagsInner;", flagsCls, flagsObject));
    // readonly soundEnabled?: NotificationFlagStatus;
    int32_t soundEnabled = static_cast<int32_t>(flags->IsSoundEnabled());
    ani_enum_item enumItem = nullptr;
    RETURN_FALSE_IF_FALSE(EnumConvertNativeToAni(env, "Lnotification/notificationFlags/NotificationFlagStatus;",
        soundEnabled, enumItem));
    RETURN_FALSE_IF_FALSE(CallSetter(env, flagsCls, flagsObject, "soundEnabled", enumItem));
    // readonly vibrationEnabled?: NotificationFlagStatus;
    int32_t vibrationEnabled = static_cast<int32_t>(flags->IsVibrationEnabled());
    RETURN_FALSE_IF_FALSE(EnumConvertNativeToAni(env, "Lnotification/notificationFlags/NotificationFlagStatus;",
        vibrationEnabled, enumItem));
    RETURN_FALSE_IF_FALSE(CallSetter(env, flagsCls, flagsObject, "vibrationEnabled", enumItem));
    // readonly reminderFlags?: number;
    uint32_t reminderFlags = flags->GetReminderFlags();
    RETURN_FALSE_IF_FALSE(CallSetterOptional(env, flagsCls, flagsObject, "reminderFlags", reminderFlags));
    return true;
}

} // namespace NotificationSts
} // OHOS