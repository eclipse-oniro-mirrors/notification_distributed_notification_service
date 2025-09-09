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
#include "ani_slot.h"

#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "ets_error_utils.h"
#include "sts_common.h"
#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_slot.h"
#include "notification_slot.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
namespace {
constexpr int32_t RETURN_EXCEPTION_VALUE  = -1;
} // namespace

ani_object AniGetSlotsByBundle(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("sts GetSlotsByBundle enter");
    int returncode = ERR_OK;
    std::vector<sptr<Notification::NotificationSlot>> slots;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::GetNotificationSlotsForBundle(option, slots);
    } else {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlotsByBundle ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts GetSlotsByBundle error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapNotificationSlotArray(env, slots, outAniObj)) {
        ANS_LOGE("WrapNotificationSlotArray failed");
        NotificationSts::ThrowStsErroWithMsg(env, "GetSlotsByBundle:failed to WrapNotificationSlotArray");
        return nullptr;
    }
    return outAniObj;
}

void AniAddSlots(ani_env *env, ani_object notificationSlotArrayObj)
{
    ANS_LOGD("AniAddSlots enter");
    std::vector<Notification::NotificationSlot> slots;
    if (!NotificationSts::UnwrapNotificationSlotArrayByAniObj(env, notificationSlotArrayObj, slots)) {
        ANS_LOGE("UnwrapNotificationSlotArrayByAniObj failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts AddSlots ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = Notification::NotificationHelper::AddNotificationSlots(slots);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AddNotificationSlots failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniAddSlots leave");
}

void AniAddSlotByNotificationSlot(ani_env *env, ani_object notificationSlotObj)
{
    ANS_LOGD("AniAddSlotByNotificationSlot enter");
    int returncode = ERR_OK;
    Notification::NotificationSlot slot;
    if (NotificationSts::UnwrapNotificationSlot(env, notificationSlotObj, slot)) {
        returncode = Notification::NotificationHelper::AddNotificationSlot(slot);
    } else {
        ANS_LOGE("UnwrapNotificationSlot failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts AddSlot ERROR_INTERNAL_ERROR");
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AddNotificationSlot failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniAddSlotByNotificationSlot leave");
}

void AniAddSlotBySlotType(ani_env *env, ani_enum_item enumObj)
{
    ANS_LOGD("AniAddSlotBySlotType enter");
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, slotType)) {
        ANS_LOGE("AniAddSlotBySlotType SlotTypeEtsToC failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AddSlotByType ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = Notification::NotificationHelper::AddSlotByType(slotType);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AddSlotByType failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniAddSlotBySlotType leave");
}

ani_object AniGetSlot(ani_env *env, ani_enum_item enumObj)
{
    ANS_LOGD("AniGetSlot enter");
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, slotType)) {
        ANS_LOGE("SlotTypeEtsToC failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlot ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    sptr<Notification::NotificationSlot> slot = nullptr;
    int returncode = Notification::NotificationHelper::GetNotificationSlot(slotType, slot);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSlot failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    if (slot == nullptr) {
        ANS_LOGD("AniGetSlot -> slot is nullptr");
        NotificationSts::ThrowError(env, RETURN_EXCEPTION_VALUE, "slot is null");
        return nullptr;
    }
    ani_object slotObj;
    if (!NotificationSts::WrapNotificationSlot(env, slot, slotObj)) {
        ANS_LOGE("WrapNotificationSlot faild");
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlot ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    ANS_LOGD("AniGetSlot leave");
    return slotObj;
}

ani_object AniGetSlots(ani_env *env)
{
    ANS_LOGD("AniGetSlots enter");
    std::vector<sptr<Notification::NotificationSlot>> slots;
    int returncode = Notification::NotificationHelper::GetNotificationSlots(slots);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSlots failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapNotificationSlotArray(env, slots, outAniObj)) {
        ANS_LOGE("WrapNotificationSlotArray faild");
        NotificationSts::ThrowStsErroWithMsg(env, "AniGetSlots:failed to WrapNotificationSlotArray");
        return nullptr;
    }
    ANS_LOGD("AniGetSlots leave");
    return outAniObj;
}

void AniRemoveSlot(ani_env *env, ani_enum_item enumObj)
{
    ANS_LOGD("AniRemoveSlot enter");
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, slotType)) {
        ANS_LOGE("SlotTypeEtsToC failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlot ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = Notification::NotificationHelper::RemoveNotificationSlot(slotType);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("RemoveNotificationSlot failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniRemoveSlot leave");
}

void AniRemoveAllSlots(ani_env *env)
{
    ANS_LOGD("AniRemoveAllSlots enter");
    int returncode = Notification::NotificationHelper::RemoveAllSlots();
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("RemoveAllSlots failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniRemoveAllSlots leave");
}

void AniSetSlotByBundle(ani_env *env, ani_object bundleOptionObj, ani_object slotObj)
{
    ANS_LOGD("AniSetSlotByBundle enter");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOptionObj, option)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts AniSetSlotByBundle ERROR_INTERNAL_ERROR");
        return;
    }

    Notification::NotificationSlot slot;
    if (!NotificationSts::UnwrapNotificationSlot(env, slotObj, slot)) {
        ANS_LOGE("UnwrapNotificationSlot failed");
        NotificationSts::ThrowStsErroWithMsg(env, "sts SetSlotByBundle ERROR_INTERNAL_ERROR");
        return;
    }

    std::vector<sptr<Notification::NotificationSlot>> slotsVct;
    sptr<Notification::NotificationSlot> slotPtr = new (std::nothrow) Notification::NotificationSlot(slot);
    if (slotPtr == nullptr) {
        ANS_LOGE("Failed to create NotificationSlot ptr");
        NotificationSts::ThrowStsErroWithMsg(env, "sts AniSetSlotByBundle ERROR_INTERNAL_ERROR");
        return;
    }
    slotsVct.emplace_back(slotPtr);

    int returncode = Notification::NotificationHelper::UpdateNotificationSlots(option, slotsVct);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("UpdateNotificationSlots failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniSetSlotByBundle leave");
}

ani_long AniGetSlotNumByBundle(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniGetSlotNumByBundle enter");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniGetSlotNumByBundle ERROR_INTERNAL_ERROR");
        return RETURN_EXCEPTION_VALUE;
    }
    uint64_t num = 0;
    int returncode = Notification::NotificationHelper::GetNotificationSlotNumAsBundle(option, num);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSlotNumAsBundle failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return RETURN_EXCEPTION_VALUE;
    }
    ani_long retNum = static_cast<ani_long>(num);
    ANS_LOGD("AniGetSlotNumByBundle leave");
    return retNum;
}
void AniSetNotificationEnableSlot(ani_env *env, ani_object bundleOption, ani_enum_item  type, ani_boolean enable)
{
    ANS_LOGD("AniSetNotificationEnableSlot enter ");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        return;
    }
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, type, slotType)) {
        ANS_LOGE("SlotTypeEtsToC failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        return;
    }
    bool isForceControl = false;
    int returncode = Notification::NotificationHelper::SetEnabledForBundleSlot(option, slotType,
        NotificationSts::AniBooleanToBool(enable), isForceControl);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("SetEnabledForBundleSlot failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniSetNotificationEnableSlot end");
}

void AniSetNotificationEnableSlotWithForce(ani_env *env,
    ani_object bundleOption, ani_enum_item  type, ani_boolean enable, ani_boolean isForceControl)
{
    ANS_LOGD("AniSetNotificationEnableSlotWithForce enter ");
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!(NotificationSts::SlotTypeEtsToC(env, type, slotType))
        || !(NotificationSts::UnwrapBundleOption(env, bundleOption, option))) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "SetNotificationEnableSlotWithForce ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = Notification::NotificationHelper::SetEnabledForBundleSlot(option, slotType,
        NotificationSts::AniBooleanToBool(enable), NotificationSts::AniBooleanToBool(isForceControl));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniSetNotificationEnableSlotSync error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetNotificationEnableSlotWithForce end");
}

ani_boolean AniIsNotificationSlotEnabled(ani_env *env, ani_object bundleOption, ani_enum_item  type)
{
    ANS_LOGD("AniIsNotificationSlotEnabled enter");
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)
        || !NotificationSts::SlotTypeEtsToC(env, type, slotType)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "IsNotificationSlotEnabled : erro arguments.");
        return ANI_FALSE;
    }
    bool isEnable = false;
    int returncode = Notification::NotificationHelper::GetEnabledForBundleSlot(option, slotType, isEnable);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetEnabledForBundleSlot failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniIsNotificationSlotEnabled end");
    return isEnable ? ANI_TRUE : ANI_FALSE;
}

ani_long AniGetSlotFlagsByBundle(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniGetSlotFlagsByBundle enter");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniGetSlotFlagsByBundle : erro arguments.");
        return ANI_FALSE;
    }
    uint32_t slotFlags = 0;
    int returncode = Notification::NotificationHelper::GetNotificationSlotFlagsAsBundle(option, slotFlags);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSlotFlagsAsBundle failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniGetSlotFlagsByBundle end");
    return slotFlags;
}

void AniSetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_long slotFlags)
{
    ANS_LOGD("AniSetSlotFlagsByBundle enter");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniSetSlotFlagsByBundle : erro arguments.");
        return;
    }
    int returncode =
        Notification::NotificationHelper::SetNotificationSlotFlagsAsBundle(option, static_cast<uint32_t>(slotFlags));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("SetNotificationSlotFlagsAsBundle failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }

    ANS_LOGD("AniSetSlotFlagsByBundle end");
}

ani_object AniGetSlotByBundle(ani_env *env, ani_object bundleOption, ani_enum_item type)
{
    ANS_LOGD("AniGetSlotByBundle enter");
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)
        || !NotificationSts::SlotTypeEtsToC(env, type, slotType)) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowStsErroWithMsg(env, "GetSlotByBundle : erro arguments.");
        return nullptr;
    }
    sptr<Notification::NotificationSlot> slot = nullptr;
    int returncode = Notification::NotificationHelper::GetNotificationSlotForBundle(option, slotType, slot);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSlotForBundle failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object infoObj;
    if (!NotificationSts::WrapNotificationSlot(env, slot, infoObj) || infoObj == nullptr) {
        ANS_LOGE("WrapNotificationSlot failed");
        NotificationSts::ThrowStsErroWithMsg(env, "WrapNotificationSlot Failed");
        return nullptr;
    }
    ANS_LOGD("AniGetSlotByBundle end");
    return infoObj;
}

ani_object AniGetNotificationSetting(ani_env *env)
{
    ANS_LOGD("AniGetNotificationSetting enter");
    uint32_t slotFlags = 0;
    int returncode = Notification::NotificationHelper::GetNotificationSettings(slotFlags);
    ANS_LOGD("AniGetNotificationSetting slotFlags: %{public}d", slotFlags);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetNotificationSettings failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object infoObj;
    if (!NotificationSts::WrapGetNotificationSetting(env, slotFlags, infoObj) || infoObj == nullptr) {
        ANS_LOGE("WrapGetNotificationSetting failed");
        NotificationSts::ThrowStsErroWithMsg(env, "WrapGetNotificationSetting Failed");
        return nullptr;
    }
    ANS_LOGD("AniGetNotificationSetting end");
    return infoObj;
}
}
}