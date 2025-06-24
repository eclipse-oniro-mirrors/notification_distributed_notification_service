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
bool SetOptionalFieldSlotLevel(
    ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName, const SlotLevel value)
{
    ANS_LOGD("SetOptionalFieldSlotLevel call");
    if (env == nullptr || cls == nullptr || object == nullptr) {
        ANS_LOGE("SetOptionalFieldSlotLevel failed, has nullptr");
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
    NotificationSts::SlotLevelCToEts(env, value, enumItem);
    if (enumItem == nullptr) {
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

bool SetOptionalFieldSlotType(
    ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName, const SlotType value)
{
    ANS_LOGD("SetOptionalFieldSlotType call");
    if (env == nullptr || cls == nullptr || object == nullptr) {
        ANS_LOGE("SetOptionalFieldSlotType failed, has nullptr");
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
    NotificationSts::SlotTypeCToEts(env, value, enumItem);
    if (enumItem == nullptr) {
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

bool WrapNotificationSlotByBoolean(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj)
{
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

bool WrapNotificationSlotByString(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj)
{
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

bool WrapNotificationSlotByDouble(ani_env *env, sptr<Notification::NotificationSlot> slot, ani_object &outAniObj)
{
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
    if (cls == nullptr || outAniObj == nullptr) {
        ANS_LOGE("Create class failed");
        return false;
    }

    if (!SetOptionalFieldSlotType(env, cls, outAniObj, "notificationType", slot->GetType())) {
        ANS_LOGE("Set notificationType fail");
        return false;
    }
    if (!SetOptionalFieldSlotLevel(env, cls, outAniObj, "notificationLevel", slot->GetLevel())) {
        ANS_LOGE("Set notificationLevel fail");
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
    if (!SetOptionalFieldArrayDouble(env, cls, outAniObj, "vibrationValues", slot->GetVibrationStyle())) {
        ANS_LOGE("Set vibrationValues fail");
        return false;
    }
    ANS_LOGD("WrapNotificationSlot end");
    return true;
}

bool WrapNotificationSlotArray(ani_env *env, const std::vector<sptr<Notification::NotificationSlot>>& slots,
    ani_object &outAniObj)
{
    ANS_LOGD("WrapNotificationSlotArray call");
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

bool ParseNotificationSlotByBasicType(ani_env *env, ani_object notificationSlotObj, NotificationSlot &slot)
{
    if (notificationSlotObj == nullptr) {
        ANS_LOGE("notificationSlotObj is null");
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    std::string desc = "";
    if (GetPropertyString(env, notificationSlotObj, "desc", isUndefined, desc) == ANI_OK && isUndefined == ANI_FALSE) {
        slot.SetDescription(GetResizeStr(desc, STR_MAX_SIZE));
    }
    std::string sound = "";
    if (GetPropertyString(env, notificationSlotObj, "sound", isUndefined, sound) == ANI_OK &&
        isUndefined == ANI_FALSE) {
        slot.SetSound(Uri(GetResizeStr(sound, STR_MAX_SIZE)));
    }
    ani_double doubleValue = 0.0;
    if (GetPropertyDouble(env, notificationSlotObj, "lockscreenVisibility", isUndefined, doubleValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.SetLockscreenVisibleness(
                Notification::NotificationConstant::VisiblenessType(static_cast<int32_t>(doubleValue)));
    }
    if (GetPropertyDouble(env, notificationSlotObj, "lightColor", isUndefined, doubleValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.SetLedLightColor(static_cast<int32_t>(doubleValue));
    }
    bool boolValue = true;
    if (GetPropertyBool(env, notificationSlotObj, "badgeFlag", isUndefined, boolValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.EnableBadge(boolValue);
    }
    if (GetPropertyBool(env, notificationSlotObj, "bypassDnd", isUndefined, boolValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.EnableBypassDnd(boolValue);
    }
    if (GetPropertyBool(env, notificationSlotObj, "lightEnabled", isUndefined, boolValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.SetEnableLight(boolValue);
    }
    if (GetPropertyBool(env, notificationSlotObj, "vibrationEnabled", isUndefined, boolValue) == ANI_OK
        && isUndefined == ANI_FALSE) {
            slot.SetEnableVibration(boolValue);
    }
    return true;
}

bool UnwrapNotificationSlot(ani_env *env, ani_object notificationSlotObj, NotificationSlot &slot)
{
    ANS_LOGD("UnwrapNotificationSlot enter");
    if (notificationSlotObj == nullptr) {
        ANS_LOGE("notificationSlotObj is null");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref notificationTypeRef = {};
    status = GetPropertyRef(env, notificationSlotObj, "notificationType", isUndefined, notificationTypeRef);
    if (status == ANI_OK && isUndefined == ANI_FALSE) {
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
        if (SlotTypeEtsToC(env, static_cast<ani_enum_item>(notificationTypeRef), slotType)) {
            slot.SetType(slotType);
        }
    }
    status = GetPropertyRef(env, notificationSlotObj, "notificationLevel", isUndefined, notificationTypeRef);
    if (status == ANI_OK && isUndefined == ANI_FALSE) {
        NotificationSlot::NotificationLevel outLevel {NotificationSlot::NotificationLevel::LEVEL_NONE};
        if (SlotLevelEtsToC(env, static_cast<ani_enum_item>(notificationTypeRef), outLevel)) {
            slot.SetLevel(outLevel);
        }
    }
    if (!ParseNotificationSlotByBasicType(env, notificationSlotObj, slot)) {
        ANS_LOGE("ParseNotificationSlotByBasicType failed");
        return false;
    }
    std::vector<int64_t> vibrationValues;
    if (GetPropertyNumberArray(env, notificationSlotObj, "vibrationValues", isUndefined, vibrationValues) == ANI_OK &&
        isUndefined == ANI_FALSE) {
        slot.SetVibrationStyle(vibrationValues);
    }
    ANS_LOGD("UnwrapNotificationSlot leave");
    return true;
}

bool UnwrapNotificationSlotArrayByAniObj(ani_env *env, ani_object notificationSlotArrayObj,
    std::vector<NotificationSlot> &slots)
{
    ANS_LOGD("UnwrapNotificationSlotArrayByAniObj enter");
    if (notificationSlotArrayObj == nullptr) {
        ANS_LOGE("notificationSlotArrayObj is null");
        return false;
    }
    ani_double length;
    ani_status status = env->Object_GetPropertyByName_Double(notificationSlotArrayObj, "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Double faild. status : %{public}d", status);
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref notificationSlotEntryRef;
        status = env->Object_CallMethodByName_Ref(notificationSlotArrayObj,
            "$_get", "I:Lstd/core/Object;", &notificationSlotEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGE("Object_CallMethodByName_Ref faild. status : %{public}d", status);
        }
        NotificationSlot slot;
        if (!UnwrapNotificationSlot(env, static_cast<ani_object>(notificationSlotEntryRef), slot)) {
            ANS_LOGE("UnwrapNotificationSlot faild");
            return false;
        }
        slots.emplace_back(slot);
    }
    ANS_LOGD("UnwrapNotificationSlotArrayByAniObj leave");
    return true;
}
} // namespace NotificationSts
} // OHOS
