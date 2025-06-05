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
#include "ani_notification_enable.h"

#include "inner_errors.h"
#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"

namespace OHOS {
namespace NotificationManagerSts {
ani_boolean AniIsNotificationEnabled(ani_env *env)
{
    ANS_LOGD("AniIsNotificationEnabled call");
    bool allowed = false;
    int returncode = Notification::NotificationHelper::IsAllowedNotifySelf(allowed);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsNotificationEnabled -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniIsNotificationEnabled end");
    return NotificationSts::BoolToAniBoolean(allowed);
}

ani_boolean AniIsNotificationEnabledWithId(ani_env *env, ani_double userId)
{
    ANS_LOGD("AniIsNotificationEnabledWithId call");
    bool allowed = false;
    int returncode = Notification::NotificationHelper::IsAllowedNotify(userId, allowed);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsNotificationEnabledWithId -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniIsNotificationEnabledWithId end");
    return NotificationSts::BoolToAniBoolean(allowed);
}

ani_boolean AniIsNotificationEnabledWithBundleOption(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniIsNotificationEnabledWithBundleOption call");
    int returncode = ERR_OK;
    bool allowed = false;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::IsAllowedNotify(option, allowed);
    } else {
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlotsByBundle ERROR_INTERNAL_ERROR");
        return ANI_FALSE;
    }

    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsNotificationEnabledWithBundleOption -> error, errorCode: %{public}d", externalCode);
        return ANI_FALSE;
    }
    ANS_LOGD("AniIsNotificationEnabledWithBundleOption end");
    return NotificationSts::BoolToAniBoolean(allowed);
}

void AniSetNotificationEnable(ani_env *env, ani_object bundleOption, ani_boolean enable)
{
    ANS_LOGD("AniSetNotificationEnable call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlotsByBundle ERROR_INTERNAL_ERROR");
        return ;
    }
    std::string deviceId {""};
    int returncode = Notification::NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(option, deviceId,
        NotificationSts::AniBooleanToBool(enable));
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetNotificationEnable -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniSetNotificationEnable end");
}

ani_object AniGetAllNotificationEnabledBundles(ani_env *env)
{
    ANS_LOGD("AniGetAllNotificationEnabledBundles call");
    std::vector<BundleOption> bundleOptions = {};
    int returncode = Notification::NotificationHelper::GetAllNotificationEnabledBundles(bundleOptions);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        ANS_LOGE("AniGetAllNotificationEnabledBundles -> error, errorCode: %{public}d", externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object arrayBundles = NotificationSts::GetAniArrayBundleOption(env, bundleOptions);
    if (arrayBundles == nullptr) {
        ANS_LOGE("GetAniArrayBundleOption filed,arrayBundles is nullptr");
        NotificationSts::ThrowStsErroWithMsg(env, "GetAniArrayBundleOption ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    return arrayBundles;
}

ani_boolean AniIsNotificationEnabledSync(ani_env *env)
{
    ANS_LOGD("AniIsNotificationEnabledSync call");
    bool allowed = false;
    int returncode = Notification::NotificationHelper::IsAllowedNotifySelf(allowed);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        ANS_LOGE("AniIsNotificationEnabledSync -> error, errorCode: %{public}d", externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    return NotificationSts::BoolToAniBoolean(allowed);
}

ani_boolean AniGetSyncNotificationEnabledWithoutApp(ani_env* env, ani_double userId)
{
    ANS_LOGD("AniGetSyncNotificationEnabledWithoutApp call");
    bool enabled = false;
    int returncode = Notification::NotificationHelper::GetSyncNotificationEnabledWithoutApp(
        static_cast<int32_t>(userId), enabled);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        ANS_LOGE("AniGetSyncNotificationEnabledWithoutApp -> error, errorCode: %{public}d", externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("End success, enabled: %{public}d, returncode: %{public}d", enabled, externalCode);
    return NotificationSts::BoolToAniBoolean(enabled);
}

void AniSetSyncNotificationEnabledWithoutApp(ani_env* env, ani_double userId, ani_boolean enabled)
{
    ANS_LOGD("AniSetSyncNotificationEnabledWithoutApp call,enable : %{public}d", enabled);
    int returncode = Notification::NotificationHelper::SetSyncNotificationEnabledWithoutApp(
        static_cast<int32_t>(userId), NotificationSts::AniBooleanToBool(enabled));
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        ANS_LOGE("AniSetSyncNotificationEnabledWithoutApp -> error, errorCode: %{public}d", externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniSetSyncNotificationEnabledWithoutApp end");
}

void AniDisableNotificationFeature(ani_env *env, ani_boolean disabled, ani_object bundleList)
{
    ANS_LOGD("AniDisableNotificationFeature enter");
    std::vector<std::string> bundleListStd;
    if (NotificationSts::GetStringArrayByAniObj(env, bundleList, bundleListStd) != ANI_OK) {
        std::string msg = "Invalid bundleList: must be an array of strings.";
        ANS_LOGE("GetStringArrayByAniObj failed. msg: %{public}s", msg.c_str());
        OHOS::AbilityRuntime::ThrowStsError(env, Notification::ERROR_PARAM_INVALID, msg);
        return;
    }
    Notification::NotificationDisable param;
    param.SetDisabled(NotificationSts::AniBooleanToBool(disabled));
    param.SetBundleList(bundleListStd);

    int returncode = ERR_OK;
    returncode = Notification::NotificationHelper::DisableNotificationFeature(param);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != ERR_OK) {
        ANS_LOGE("AniDisableNotificationFeature error, errorCode: %{public}d", externalCode);
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}
} // namespace NotificationManagerSts
} // namespace OHOS