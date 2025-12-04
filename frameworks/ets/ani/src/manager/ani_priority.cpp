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

#include "ani_priority.h"

#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetBundlePriorityConfig(ani_env* env, ani_object obj, ani_string value)
{
    std::string valueStr = "";
    if (NotificationSts::GetStringByAniString(env, value, valueStr) != ANI_OK) {
        ANS_LOGE("sts setBundlePriorityConfig failed cause invalid value");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        return;
    }
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("sts setBundlePriorityConfig failed cause invalid bundle");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        return;
    }
    int returncode = Notification::NotificationHelper::SetBundlePriorityConfig(option, valueStr);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts setBundlePriorityConfig failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_string AniGetBundlePriorityConfig(ani_env* env, ani_object obj)
{
    ani_string outAniStr;
    std::string config = "";
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("sts getBundlePriorityConfig failed cause invalid bundle");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        NotificationSts::GetAniStringByString(env, config, outAniStr);
        return outAniStr;
    }
    int returncode = Notification::NotificationHelper::GetBundlePriorityConfig(option, config);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts getBundlePriorityConfig error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    NotificationSts::GetAniStringByString(env, config, outAniStr);
    return outAniStr;
}

void AniSetPriorityEnabledByBundle(ani_env* env, ani_object obj, ani_enum_item enableStatus)
{
    OHOS::Notification::NotificationConstant::PriorityEnableStatus status =
        OHOS::Notification::NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    if (!NotificationSts::EnumConvertAniToNative(env, enableStatus, status)) {
        ANS_LOGE("sts setPriorityEnabledByBundle failed cause invalid enableStatus");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        return;
    }
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("sts setPriorityEnabledByBundle failed cause invalid bundle");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        return;
    }
    int returncode = Notification::NotificationHelper::SetPriorityEnabledByBundle(option, status);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts setPriorityEnabledByBundle failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_object AniIsPriorityEnabledByBundle(ani_env* env, ani_object obj)
{
    ani_enum_item statusItem {};
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        ANS_LOGE("sts isPriorityEnabledByBundle failed cause invalid bundle");
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID,
            NotificationSts::FindAnsErrMsg(Notification::ERROR_PARAM_INVALID));
        return statusItem;
    }
    OHOS::Notification::NotificationConstant::PriorityEnableStatus status =
        OHOS::Notification::NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    int returncode = Notification::NotificationHelper::IsPriorityEnabledByBundle(option, status);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts isPriorityEnabledByBundle failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    NotificationSts::EnumConvertNativeToAni(env,
        "@ohos.notificationManager.notificationManager.PriorityEnableStatus", status, statusItem);
    return statusItem;
}

void AniSetPriorityEnabled(ani_env* env, ani_boolean enable)
{
    int returncode = Notification::NotificationHelper::SetPriorityEnabled(NotificationSts::AniBooleanToBool(enable));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts setPriorityEnabled failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_boolean AniIsPriorityEnabled(ani_env* env)
{
    bool enable = true;
    int returncode = Notification::NotificationHelper::IsPriorityEnabled(enable);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts isPriorityEnabled failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    return NotificationSts::BoolToAniBoolean(enable);
}
} // namespace NotificationManagerSts
} // namespace OHOS