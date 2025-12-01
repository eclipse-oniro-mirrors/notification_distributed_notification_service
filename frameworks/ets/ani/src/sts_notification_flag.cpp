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
bool GetNotificationFlagStatus(
    ani_env* env, const ani_object obj, const char *name, NotificationFlagStatus &flag)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref flagStatusRef = {};
    if (GetPropertyRef(env, obj, name, isUndefined, flagStatusRef) == ANI_OK
        && isUndefined == ANI_FALSE && flagStatusRef != nullptr) {
        if (EnumConvertAniToNative(env, static_cast<ani_enum_item>(flagStatusRef), flag)) {
            return true;
        }
    }
    return false;
}

bool SetNotificationFlagStatus(ani_env* env,
    const char *name, const int32_t flagEnabled, ani_object &flagsObject)
{
    ani_enum_item enumItem = nullptr;
    if (!EnumConvertNativeToAni(env, "notification.notificationFlags.NotificationFlagStatus",
        flagEnabled, enumItem)) {
            ANS_LOGE("EnumConvertNativeToAni %{public}s faild", name);
            return false;
        }
    if (!SetPropertyByRef(env, flagsObject, name, enumItem)) {
        ANS_LOGE("SetNotificationFlagStatus %{public}s faild", name);
        return false;
    }
    return true;
}

bool WarpNotificationFlags(ani_env* env, const std::shared_ptr<NotificationFlags> &flags,
    ani_object &flagsObject)
{
    ANS_LOGD("WarpNotificationFlags call");
    if (flags == nullptr) {
        ANS_LOGE("flags is null");
        return false;
    }
    ani_class flagsCls = nullptr;
    if (!CreateClassObjByClassName(env, "notification.notificationFlags.NotificationFlagsInner",
        flagsCls, flagsObject) || flagsObject == nullptr) {
        ANS_LOGE("CreateClassObjByClassName faild");
        return false;
    }
    // soundEnabled?: NotificationFlagStatus;
    int32_t soundEnabled = static_cast<int32_t>(flags->IsSoundEnabled());
    if (!SetNotificationFlagStatus(env, "soundEnabled", soundEnabled, flagsObject)) {
        ANS_LOGE("WarpNotificationFlags set 'soundEnabled' faild");
        return false;
    }
    // vibrationEnabled?: NotificationFlagStatus;
    int32_t vibrationEnabled = static_cast<int32_t>(flags->IsVibrationEnabled());
    if (!SetNotificationFlagStatus(env, "vibrationEnabled", vibrationEnabled, flagsObject)) {
        ANS_LOGE("WarpNotificationFlags set 'vibrationEnabled' faild");
        return false;
    }
    // bannerEnabled?: NotificationFlagStatus;
    int32_t bannerEnabled = static_cast<int32_t>(flags->IsBannerEnabled());
    if (!SetNotificationFlagStatus(env, "bannerEnabled", bannerEnabled, flagsObject)) {
        ANS_LOGE("WarpNotificationFlags set 'bannerEnabled' faild");
        return false;
    }
    // lockScreenEnabled?: NotificationFlagStatus;
    int32_t lockScreenEnabled = static_cast<int32_t>(flags->IsLockScreenEnabled());
    if (!SetNotificationFlagStatus(env, "lockScreenEnabled", lockScreenEnabled, flagsObject)) {
        ANS_LOGE("WarpNotificationFlags set 'lockScreenEnabled' faild");
        return false;
    }
    // readonly reminderFlags?: long;
    uint32_t reminderFlags = flags->GetReminderFlags();
    if (!SetPropertyOptionalByLong(env, flagsObject, "reminderFlags", static_cast<int64_t>(reminderFlags))) {
        ANS_LOGD("WarpNotificationFlags set 'reminderFlags' faild");
    }
    return true;
}
} // namespace NotificationSts
} // OHOS