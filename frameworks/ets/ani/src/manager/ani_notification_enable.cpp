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
    int returncode = Notification::NotificationHelper::IsAllowedNotify(allowed);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
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
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsNotificationEnabledWithId -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniIsNotificationEnabledWithId end");
    return NotificationSts::BoolToAniBoolean(allowed);
}

ani_boolean AniIsNotificationEnabledWithBundleOption(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniIsNotificationEnabledWithBundleOption call");
    int returncode = 0;
    bool allowed = false;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::IsAllowedNotify(option, allowed);
    } else {
        NotificationSts::ThrowStsErroWithMsg(env, "sts GetSlotsByBundle ERROR_INTERNAL_ERROR");
        return ANI_FALSE;
    }

    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
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
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetNotificationEnable -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniSetNotificationEnable end");
}
} // namespace NotificationManagerSts
} // namespace OHOS