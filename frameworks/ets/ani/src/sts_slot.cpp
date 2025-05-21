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
#include "sts_slot.h"

#include "ans_log_wrapper.h"
#include "sts_notification_manager.h"
#include "sts_common.h"


namespace OHOS {
namespace NotificationSts {
bool SetOptionalFieldSlotType(ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName,
    const SlotType value)
{
    ANS_LOGD("WrapNotificationSlot call");
    if (env == nullptr || cls == nullptr) {
        ANS_LOGE("WrapNotificationSlot failed, has nullptr");
        return false;
    }
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(cls);
    RETURN_FALSE_IF_NULL(object);
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_enum_item enumItem = nullptr;
    NotificationSts::SlotTypeCToEts(env, value, enumItem);
    if (enumItem == nullptr)
    {
        ANS_LOGE("null enumItem");
        return false;
    }    
    status = env->Object_SetField_Ref(object, field, enumItem);
    if (status != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}
bool WrapNotificationSlotByBoolean(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj) {
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "badgeFlag", slot->IsShowBadge())) {
        ANS_LOGE("Set badgeFlag fail");
        return false;
    }
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "bypassDnd", slot->IsEnableBypassDnd())) {
        ANS_LOGE("Set bypassDnd fail");
        return false;
    }
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "vibrationEnabled", slot->CanVibrate())) {
        ANS_LOGE("Set vibrationEnabled fail");
        return false;
    }
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "lightEnabled", slot->CanEnableLight())) {
        ANS_LOGE("Set lightEnabled fail");
        return false;
    }
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "enabled", slot->GetEnable())) {
        ANS_LOGE("Set enabled fail");
        return false;
    }
    return true;
}

bool WrapNotificationSlotByString(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj) {
    if (!SetPropertyOptionalByString(env, outAniObj, "desc", slot->GetDescription())) {
        ANS_LOGE("Set desc fail");
        return false;
    }
    if (!SetPropertyOptionalByString(env, outAniObj, "sound", slot->GetSound().ToString().c_str())) {
        ANS_LOGE("Set sound fail");
        return false;
    }
    return true;
}

bool WrapNotificationSlotByDouble(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj) {
    if (!SetPropertyOptionalByDouble(
        env, outAniObj, "lockscreenVisibility", static_cast<double>(slot->GetLockScreenVisibleness()))) {
        ANS_LOGE("Set lockscreenVisibility fail");
        return false;
    }
    if (!SetPropertyOptionalByDouble(env, outAniObj, "lightColor", static_cast<double>(slot->GetLedLightColor()))) {
        ANS_LOGE("Set lightColor fail");
        return false;
    }
    if (!SetPropertyOptionalByDouble(env, outAniObj, "reminderMode", static_cast<double>(slot->GetReminderMode()))) {
        ANS_LOGE("Set reminderMode fail");
        return false;
    }
    if (!SetPropertyOptionalByDouble(
        env, outAniObj, "authorizedStatus", static_cast<double>(slot->GetAuthorizedStatus()))) {
        ANS_LOGE("Set authorizedStatus fail");
        return false;
    }
    return true;
}

bool WrapNotificationSlot(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj)
{
    ANS_LOGD("WrapNotificationSlot call");
    if (env == nullptr || slot == nullptr) {
        ANS_LOGE("WrapNotificationSlot failed, has nullptr");
        return false;
    }
    ani_class cls;
    if (!CreateClassObjByClassName(env, NOTIFICATION_SOLT_CLASSNAME, cls, outAniObj)) {
        ANS_LOGE("CreateClassObjByClassName fail");
        return false;
    }
    if (!SetOptionalFieldSlotType(env, cls, outAniObj, "notificationType", slot->GetType())) {
        ANS_LOGE("Set notificationType fail");
        return false;
    }
    if (!WrapNotificationSlotByBoolean(env, slot, outAniObj)) {
        ANS_LOGE("set Boolean params fail");
        return false;
    }
    if (!WrapNotificationSlotByString(env, slot, outAniObj)) {
        ANS_LOGE("set String params fail");
        return false;
    }
    if (!WrapNotificationSlotByDouble(env, slot, outAniObj)) {
        ANS_LOGE("set String params fail");
        return false;
    }
    if (!SetOptionalFieldArrayDouble(env, cls, outAniObj, "vibrationValues", slot->GetVibrationStyle()))
    {
        ANS_LOGE("Set vibrationValues fail");
        return false;
    }
    ANS_LOGD("WrapNotificationSlot end");
    return true;
}

bool SetOptionalFieldSlotLevel(ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName,
    const SlotLevel value)
{
    ANS_LOGD("SetOptionalFieldSlotLevel call");
    if (env == nullptr) {
        ANS_LOGE("SetOptionalFieldSlotLevel failed, env is nullptr");
        return false;
    }
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_enum_item enumItem = nullptr;
    if (!NotificationSts::SlotLevelCToEts(env, value, enumItem) || enumItem == nullptr)
    {
        ANS_LOGE("get enumItem failed");
        return false;
    }    
    status = env->Object_SetField_Ref(object, field, enumItem);
    if (status != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}

bool WrapNotificationSlotArray(ani_env *env, const std::vector<sptr<Notification::NotificationSlot>>& slots,
    ani_object &outAniObj)
{
    ANS_LOGD("WrapNotificationSlotArray call");
    if (slots.empty()) {
        ANS_LOGD("slots is empty");
        return false;
    }
    outAniObj = newArrayClass(env, slots.size());
    if (outAniObj == nullptr) {
        ANS_LOGE("outAniObj is null, newArrayClass Faild");
        return false;
    }
    int index = 0;
    for (auto &it : slots) {
        ani_object infoObj;
        if (!WrapNotificationSlot(env, it, infoObj) || infoObj == nullptr) {
            ANS_LOGE("WrapNotificationSlot Faild. index = %{public}d", index);
            return false;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(outAniObj, "$_set", "ILstd/core/Object;:V", index, infoObj)) {
            ANS_LOGE("set Faild. index = %{public}d", index);
            return false;
        }
        index++;
    }
    ANS_LOGD("WrapNotificationSlotArray end");
    return true;
}
} // namespace NotificationSts
} // OHOS
