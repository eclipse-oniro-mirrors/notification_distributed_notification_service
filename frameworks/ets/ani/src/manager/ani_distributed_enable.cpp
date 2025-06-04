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

#include "inner_errors.h"
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
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != CJSystemapi::Notification::SUCCESS_CODE) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
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
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != CJSystemapi::Notification::SUCCESS_CODE) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsDistributedEnabled -> error, errorCode: %{public}d", externalCode);
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("AniIsDistributedEnabled end, enabled: %{public}d, returncode: %{public}d", enabled, externalCode);
    return NotificationSts::BoolToAniBoolean(enabled);
}

ani_boolean AniIsDistributedEnabledByBundle(ani_env* env, ani_object obj)
{
    ANS_LOGD("AniIsDistributedEnabledByBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniIsDistributedEnabledByBundle : erro arguments.");
        return NotificationSts::BoolToAniBoolean(false);
    }
    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnableByBundle(option, enabled);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != CJSystemapi::Notification::SUCCESS_CODE) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsDistributedEnabledByBundle -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniIsDistributedEnabledByBundle end, enabled: %{public}d, returncode: %{public}d", enabled, externalCode);
    return NotificationSts::BoolToAniBoolean(enabled);
}

ani_boolean AniIsDistributedEnabledByBundleType(ani_env* env, ani_object obj, ani_string deviceType)
{
    ANS_LOGD("AniIsDistributedEnabledByBundleType call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, obj, option)) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniIsDistributedEnabledByBundleType : erro arguments.");
        return NotificationSts::BoolToAniBoolean(false);
    }
    std::string deviceTypeStr;
    if (NotificationSts::GetStringByAniString(env, deviceType, deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowStsErroWithMsg(env, "deviceType parse failed!");
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("Cancel by deviceType:%{public}s", deviceTypeStr.c_str());

    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsDistributedEnabledByBundle(option, deviceTypeStr, enabled);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != CJSystemapi::Notification::SUCCESS_CODE) {
        AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsDistributedEnabledByBundle -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniIsDistributedEnabledByBundle end, enabled: %{public}d, returncode: %{public}d", enabled, externalCode);
    return NotificationSts::BoolToAniBoolean(enabled);
}
}
}