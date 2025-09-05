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
#include "ani_distributed_enable.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetDistributedEnable(ani_env* env, ani_boolean enabled)
{
    ANS_LOGD("AniSetDistributedEnable call,enable : %{public}d", enabled);
    int returncode = Notification::NotificationHelper::EnableDistributed(NotificationSts::AniBooleanToBool(enabled));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetDistributedEnable -> error, errorCode: %{public}d", externalCode);
        return;
    }
    ANS_LOGD("AniSetDistributedEnable end");
}

ani_boolean AniIsDistributedEnabled(ani_env* env)
{
    ANS_LOGD("AniIsDistributedEnabled call");
    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnabled(enabled);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniIsDistributedEnabled -> error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("AniIsDistributedEnabled end");
    return NotificationSts::BoolToAniBoolean(enabled);
}

ani_boolean AniIsDistributedEnabledByBundle(ani_env* env, ani_object obj)
{
    ANS_LOGD("AniIsDistributedEnabledByBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniIsDistributedEnabledByBundle : erro arguments.");
        return NotificationSts::BoolToAniBoolean(false);
    }
    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnableByBundle(option, enabled);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniIsDistributedEnabledByBundle -> error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniIsDistributedEnabledByBundle end");
    return NotificationSts::BoolToAniBoolean(enabled);
}

ani_boolean AniIsDistributedEnabledByBundleType(ani_env* env, ani_object obj, ani_string deviceType)
{
    ANS_LOGD("AniIsDistributedEnabledByBundleType call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniIsDistributedEnabledByBundleType : erro arguments.");
        return NotificationSts::BoolToAniBoolean(false);
    }
    std::string deviceTypeStr;
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowErrorWithMsg(env, "deviceType parse failed!");
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("Cancel by deviceType:%{public}s", deviceTypeStr.c_str());

    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnabledByBundle(option, deviceTypeStr, enabled);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniIsDistributedEnabledByBundle -> error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniIsDistributedEnabledByBundle end");
    return NotificationSts::BoolToAniBoolean(enabled);
}

void AniSetDistributedEnableByBundle(ani_env *env, ani_object obj, ani_boolean enable)
{
    ANS_LOGD("setDistributedEnableByBundle call");
    int returncode = ERR_OK;
    Notification::NotificationBundleOption option;
    bool bFlag = NotificationSts::UnwrapBundleOption(env, obj, option);
    if (bFlag) {
        returncode = Notification::NotificationHelper::EnableDistributedByBundle(
            option, NotificationSts::AniBooleanToBool(enable));
    } else {
        ANS_LOGE("sts setDistributedEnableByBundle ERROR_INTERNAL_ERROR");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts setDistributedEnableByBundle error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("sts setDistributedEnableByBundle end");
}

void AniSetDistributedEnableByBundleAndType(ani_env *env,
    ani_object obj, ani_string deviceType, ani_boolean enable)
{
    ANS_LOGD("sts setDistributedEnabledByBundle call");
    std::string deviceTypeStr;
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    int returncode = ERR_OK;
    Notification::NotificationBundleOption option;
    bool bFlag = NotificationSts::UnwrapBundleOption(env, obj, option);
    if (bFlag) {
        returncode = Notification::NotificationHelper::SetDistributedEnabledByBundle(option,
            deviceTypeStr, NotificationSts::AniBooleanToBool(enable));
    } else {
        ANS_LOGE("sts setDistributedEnabledByBundle ERROR_INTERNAL_ERROR");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts setDistributedEnabledByBundle error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("sts setDistributedEnabledByBundle end");
}

void AniSetTargetDeviceStatus(ani_env* env, ani_string deviceType, ani_double status)
{
    ANS_LOGD("sts setTargetDeviceStatus call, id:%{public}lf", status);
    std::string deviceTypeStr;
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    ANS_LOGD("sts setTargetDeviceStatus id:%{public}lf deviceType:%{public}s", status, deviceTypeStr.c_str());
    int32_t ret = Notification::NotificationHelper::SetTargetDeviceStatus(deviceTypeStr, status, DISTURB_DEFAULT_FLAG);
    if (ret != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGE("sts setTargetDeviceStatus error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("sts setTargetDeviceStatus end");
}

ani_boolean AniIsSmartReminderEnabled(ani_env *env, ani_string deviceType)
{
    ANS_LOGD("isSmartReminderEnabled call");
    bool allowed = false;
    std::string deviceTypeStr;
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return ANI_FALSE;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return ANI_FALSE;
    }
    int returncode = Notification::NotificationHelper::IsSmartReminderEnabled(deviceTypeStr, allowed);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("isSmartReminderEnabled -> error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("isSmartReminderEnabled end");
    return NotificationSts::BoolToAniBoolean(allowed);
}


void AniSetSmartReminderEnable(ani_env *env, ani_string deviceType, ani_boolean enable)
{
    ANS_LOGD("setSmartReminderEnabled call");
    std::string deviceTypeStr;
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return;
    }

    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    int returncode = Notification::NotificationHelper::SetSmartReminderEnabled(deviceTypeStr,
        NotificationSts::AniBooleanToBool(enable));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("setSmartReminderEnabled -> error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("setSmartReminderEnabled end");
}

void AniSetDistributedEnableBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType, ani_boolean enable)
{
    ANS_LOGD("setDistributedEnabledBySlot enter ");
    std::string deviceTypeStr;
    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, slot, slotType)) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("SlotTypeEtsToC failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    int returncode = ERR_OK;
    returncode = Notification::NotificationHelper::SetDistributedEnabledBySlot(slotType,
        deviceTypeStr, NotificationSts::AniBooleanToBool(enable));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("setDistributedEnabledBySlot error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_boolean AniIsDistributedEnabledBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType)
{
    ANS_LOGD("isDistributedEnabledBySlot enter");
    std::string deviceTypeStr;

    Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType::OTHER;
    if (!NotificationSts::SlotTypeEtsToC(env, slot, slotType)) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("SlotTypeEtsToC failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return ANI_FALSE;
    }
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return ANI_FALSE;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return ANI_FALSE;
    }
    bool isEnable = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnabledBySlot(slotType, deviceTypeStr, isEnable);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("isDistributedEnabledBySlot -> error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    return isEnable ? ANI_TRUE : ANI_FALSE;
}

void AniSetDistributedEnableByBundles(ani_env *env, ani_object obj, ani_string deviceType)
{
    ANS_LOGD("AniSetDistributedEnableByBundles call");
    std::string deviceTypeStr;
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        ANS_LOGE("GetStringByAniString fail");
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return;
    }
    std::vector<DistributedBundleOption> bundles;
    if (!NotificationSts::UnwrapArrayDistributedBundleOption(env, obj, bundles)) {
        ANS_LOGE("UnwrapArrayDistributedBundleOption fail");
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return;
    }
    int returncode = Notification::NotificationHelper::SetDistributedBundleOption(bundles, deviceTypeStr);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniSetDistributedEnableByBundles error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetDistributedEnableByBundles end");
}

void AniSetDistributedEnabled(ani_env *env, ani_boolean enable, ani_string deviceType)
{
    ANS_LOGD("AniSetDistributedEnabled call");
    std::string deviceTypeStr;
    if (env == nullptr || deviceType == nullptr) {
        ANS_LOGE("Invalid env or deviceType is null");
        return;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        ANS_LOGE("GetStringByAniString fail");
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return;
    }
    int returncode = Notification::NotificationHelper::SetDistributedEnabled(deviceTypeStr,
        NotificationSts::AniBooleanToBool(enable));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniSetDistributedEnabled error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetDistributedEnabled end");
}

ani_object AniGetDistributedDeviceList(ani_env *env)
{
    ANS_LOGD("AniGetDistributedDeviceList call");
    std::vector<std::string> deviceList;
    int returncode = Notification::NotificationHelper::GetDistributedDevicelist(deviceList);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetDistributedDeviceList error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("GetDistributedDevicelist deviceList size: %{public}d", static_cast<int32_t>(deviceList.size()));
    ani_object deviceListArray = NotificationSts::GetAniStringArrayByVectorString(env, deviceList);
    if (deviceListArray == nullptr) {
        ANS_LOGE("deviceListArray nullptr");
        OHOS::NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERROR_INTERNAL_ERROR);
        return nullptr;
    }
    ANS_LOGD("AniGetDistributedDeviceList end");
    return deviceListArray;
}
}
}