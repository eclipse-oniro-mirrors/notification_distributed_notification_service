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
#include "sts_reminder_info.h"

#include "sts_common.h"
#include "sts_bundle_option.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
bool WrapReminderInfo(ani_env* env,
    const std::shared_ptr<ReminderInfo> &reminder, ani_object &reminderObject)
{
    ANS_LOGD("WrapReminderInfo call");
    if (env == nullptr || reminder == nullptr) {
        ANS_LOGE("WrapReminderInfo failed, has nullptr");
        return false;
    }
    ani_class reminderCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "@ohos.notificationManager.notificationManager.NotificationReminderInfoInner", reminderCls, reminderObject)
        || reminderCls == nullptr || reminderObject == nullptr) {
        ANS_LOGE("WrapReminderInfo: create reminderInfo failed");
        return false;
    }

    ani_object bundleObject;
    std::shared_ptr<BundleOption> optionSp = std::make_shared<BundleOption>(reminder->GetBundleOption());
    if (!WrapBundleOption(env, optionSp, bundleObject) || bundleObject == nullptr) {
        ANS_LOGE("WrapReminderInfo: bundleObject is nullptr");
        return false;
    }

    if (!SetPropertyByRef(env, reminderObject, "bundle", bundleObject)) {
        ANS_LOGE("Set bundle failed");
        return false;
    }

    uint32_t reminderFlags = reminder->GetReminderFlags();
    if (!SetFieldLong(env, reminderCls, reminderObject, "reminderFlags", static_cast<int64_t>(reminderFlags))) {
        ANS_LOGE("Set reminderFlags failed");
        return false;
    }

    if (!SetOptionalFieldBoolean(env, reminderCls, reminderObject,
        "silentReminderEnabled", reminder->GetSilentReminderEnabled())) {
        ANS_LOGE("Set silentReminderEnabled failed");
        return false;
    }

    ANS_LOGD("WrapReminderInfo end");
    return true;
}

ani_object GetAniArrayReminderInfo(ani_env* env, const std::vector<ReminderInfo> &reminders)
{
    ANS_LOGD("GetAniArrayReminderInfo call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayReminderInfo failed, has nullptr");
        return nullptr;
    }
    ani_array arrayObj = newArrayClass(env, reminders.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayReminderInfo: arrayObj is nullptr");
        return nullptr;
    }
    int32_t index = 0;
    for (auto &reminder : reminders) {
        std::shared_ptr<ReminderInfo> optSp = std::make_shared<ReminderInfo>(reminder);
        ani_object item;
        if (!WrapReminderInfo(env, optSp, item) || item == nullptr) {
            ANS_LOGE("GetAniArrayReminderInfo: item is nullptr");
            return nullptr;
        }
        if (ANI_OK != env->Array_Set(arrayObj, index, item)) {
            ANS_LOGE("GetAniArrayReminderInfo: Array_Set failed");
            return nullptr;
        }
        index ++;
    }
    ANS_LOGD("GetAniArrayReminderInfo end");
    return arrayObj;
}

bool UnwrapReminderInfo(ani_env *env, ani_object reminderObj, Notification::NotificationReminderInfo& reminder)
{
    ANS_LOGD("UnwrapReminderInfo call");
    if (env == nullptr || reminderObj == nullptr) {
        ANS_LOGE("UnwrapReminderInfo failed, has nullptr");
        return false;
    }

    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;

    ani_ref bundleObj = {};
    Notification::NotificationBundleOption bundle;
    status = GetPropertyRef(env, reminderObj, "bundle", isUndefined, bundleObj);
    if (status != ANI_OK || isUndefined != ANI_FALSE) {
        ANS_LOGE("UnwrapReminderInfo: get bundleObj failed");
        return false;
    }

    if (!UnwrapBundleOption(env, static_cast<ani_object>(bundleObj), bundle)) {
        ANS_LOGE("UnwrapReminderInfo: parse bundleOption failed");
        return false;
    }
    reminder.SetBundleOption(bundle);

    ani_long reminderFlagsValue = 0;
    if ((status = env->Object_GetPropertyByName_Long(reminderObj,
        "reminderFlags", &reminderFlagsValue)) != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Long failed, status : %{public}d", status);
        return false;
    }
    reminder.SetReminderFlags((static_cast<int32_t>(reminderFlagsValue)));

    ani_boolean enableValue = ANI_TRUE;
    if ((status = env->Object_GetPropertyByName_Boolean(reminderObj,
        "silentReminderEnabled", &enableValue)) != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Boolean failed, status : %{public}d", status);
        return false;
    }
    reminder.SetSilentReminderEnabled((static_cast<bool>(enableValue)));

    ANS_LOGD("UnwrapReminderInfo end");
    return true;
}

bool UnwrapArrayReminderInfo(ani_env *env, ani_ref arrayObj, std::vector<ReminderInfo>& reminders)
{
    ANS_LOGD("UnwrapArrayReminderInfo call");
    if (env == nullptr || arrayObj == nullptr) {
        ANS_LOGE("UnwrapArrayReminderInfo failed, has nullptr");
        return false;
    }

    ani_status status;
    ani_int length;
    status = env->Object_GetPropertyByName_Int(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("UnwrapArrayReminderInfo: get length failed, status = %{public}d", status);
        return false;
    }
    Notification::NotificationReminderInfo reminder;
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_ref reminderRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "i:Y", &reminderRef, i);
        if (status != ANI_OK) {
            ANS_LOGE("UnwrapArrayReminderInfo: get bundleOptionRef failed, status = %{public}d", status);
            return false;
        }
        if (!UnwrapReminderInfo(env, static_cast<ani_object>(reminderRef), reminder)) {
            ANS_LOGE("UnwrapArrayReminderInfo: get reminder failed, index = %{public}d", i);
            return false;
        }
        reminders.push_back(reminder);
    }
    ANS_LOGD("UnwrapArrayReminderInfo end");
    return true;
}
}
}
