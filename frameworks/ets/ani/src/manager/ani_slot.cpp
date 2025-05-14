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
#include "sts_error_utils.h"
#include "sts_common.h"
#include "inner_errors.h"
#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_slot.h"
#include "notification_slot.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {

ani_object AniGetSlotsByBundle(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("sts GetSlotsByBundle enter");
    int returncode = 0;
    std::vector<sptr<Notification::NotificationSlot>> slots;
    BundleOption option;
    if(NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::GetNotificationSlotsForBundle(option, slots);
    } else {
        NotificationSts::ThrowStsErroWithLog(env, "sts GetSlotsByBundle ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("sts GetSlotsByBundle error, errorCode: %{public}d", externalCode);
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapNotificationSlotArray(env, slots, outAniObj)) {
        NotificationSts::ThrowStsErroWithLog(env, "GetSlotsByBundle:failed to WrapNotificationSlotArray");
        return nullptr;
    }
    ANS_LOGD("sts GetSlotsByBundle end, ret: %{public}d", externalCode);
    return outAniObj;
}

void AniSetNotificationEnableSlot(ani_env *env, ani_object bundleOption, ani_enum_item  type, ani_boolean enable)
{
    ANS_LOGD("AniSetNotificationEnableSlot enter ");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        NotificationSts::ThrowStsErroWithLog(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        return;
    }
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, type, slotType)) {
        NotificationSts::ThrowStsErroWithLog(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = 0;
    bool isForceControl = false;
    returncode = Notification::NotificationHelper::SetEnabledForBundleSlot(option, slotType,
        NotificationSts::AniBooleanToBool(enable), isForceControl);

    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetNotificationEnableSlot error, errorCode: %{public}d", externalCode);
        return;
    }
    ANS_LOGD("AniSetNotificationEnableSlot end");
}

void AniSetNotificationEnableSlotWithForce(ani_env *env, ani_object bundleOption, ani_enum_item  type, ani_boolean enable,
    ani_object isForceControl)
{
    ANS_LOGD("AniSetNotificationEnableSlotWithForce enter ");
    ani_boolean isUndefined = false;
    ani_boolean res = 0.0;
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!(NotificationSts::SlotTypeEtsToC(env, type, slotType))
        || !(NotificationSts::UnwrapBundleOption(env, bundleOption, option))) {
        NotificationSts::ThrowStsErroWithLog(env, "SetNotificationEnableSlotWithForce ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = 0;
	env->Reference_IsUndefined(isForceControl, &isUndefined);
	if(isUndefined) {
        bool forceControl = false;
	    returncode = Notification::NotificationHelper::SetEnabledForBundleSlot(option, slotType,
            NotificationSts::AniBooleanToBool(enable), forceControl);
	} else {
        if (ANI_OK !=env->Object_CallMethodByName_Boolean(isForceControl, "booleanValue", nullptr, &res)){
            NotificationSts::ThrowStsErroWithLog(env, "SetNotificationEnableSlot Object_CallMethodByName_Boolean Fail");
            return;
        }
        returncode = Notification::NotificationHelper::SetEnabledForBundleSlot(option, slotType,
            NotificationSts::AniBooleanToBool(enable), NotificationSts::AniBooleanToBool(res));
	}
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetNotificationEnableSlotSync error, errorCode: %{public}d", externalCode);
    }
}

ani_boolean AniIsNotificationSlotEnabled(ani_env *env, ani_object bundleOption, ani_enum_item  type)
{
    ANS_LOGD("IsNotificationSlotEnabled enter");
    Notification::NotificationBundleOption option;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)
        || !NotificationSts::SlotTypeEtsToC(env, type, slotType)) {
        NotificationSts::ThrowStsErroWithLog(env, "IsNotificationSlotEnabled : erro arguments.");
        return ANI_FALSE;
    }

    bool isEnable = false;
    int returncode = Notification::NotificationHelper::GetEnabledForBundleSlot(option, slotType, isEnable);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("IsNotificationSlotEnabled -> error, errorCode: %{public}d", externalCode);
    }
    return isEnable ? ANI_TRUE : ANI_FALSE;
}

ani_int AniGetSlotFlagsByBundle(ani_env *env, ani_object obj)
{
    ANS_LOGD("sts getSlotFlagsByBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowStsErroWithLog(env, "AniGetSlotFlagsByBundle : erro arguments.");
        return ANI_FALSE;
    }
    uint32_t slotFlags = 0;
    int returncode = Notification::NotificationHelper::GetNotificationSlotFlagsAsBundle(option, slotFlags);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetSlotFlagsByBundle -> error, errorCode: %{public}d", externalCode);
    }
    return slotFlags;
}

void AniSetSlotFlagsByBundle(ani_env *env, ani_object obj)
{
    ANS_LOGD("sts setSlotFlagsByBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowStsErroWithLog(env, "AniSetSlotFlagsByBundle : erro arguments.");
        return;
    }
    uint32_t slotFlags = 0;
    int returncode = Notification::NotificationHelper::SetNotificationSlotFlagsAsBundle(option, slotFlags);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetSlotFlagsByBundle -> error, errorCode: %{public}d", externalCode);
    }
}
}
}