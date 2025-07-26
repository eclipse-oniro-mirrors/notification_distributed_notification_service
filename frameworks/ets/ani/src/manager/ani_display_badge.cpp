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
#include "ani_display_badge.h"

#include "ans_log_wrapper.h"
#include "sts_bundle_option.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_helper.h"
#include "notification_bundle_option.h"


namespace OHOS {
namespace NotificationManagerSts {
void AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable)
{
    ANS_LOGD("DisplayBadgeAni call");
    int returncode = 0;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
        returncode = Notification::NotificationHelper::SetShowBadgeEnabledForBundle(option,
            NotificationSts::AniBooleanToBool(enable));
    } else {
        OHOS::NotificationSts::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("sts DisplayBadge ERROR_INTERNAL_ERROR");
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts DisplayBadge error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("DisplayBadgeAni end");
}

ani_boolean AniIsBadgeDisplayed(ani_env *env, ani_object obj)
{
    ANS_LOGD("sts IsBadgeDisplayed call");
    int returncode = 0;
    bool isDisplayed = false;
    if (obj == nullptr) {
        returncode = Notification::NotificationHelper::GetShowBadgeEnabled(isDisplayed);
    } else {
        BundleOption option;
        if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
            returncode = Notification::NotificationHelper::GetShowBadgeEnabledForBundle(option, isDisplayed);
        } else {
            OHOS::NotificationSts::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            ANS_LOGE("sts IsBadgeDisplayed ERROR_INTERNAL_ERROR");
            return NotificationSts::BoolToAniBoolean(false);
        }
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts IsBadgeDisplayed error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("sts IsBadgeDisplayed end, isDisplayed: %{public}d", isDisplayed);
    return NotificationSts::BoolToAniBoolean(isDisplayed);
}

void AniSetBadgeNumber(ani_env *env, ani_double badgeNumber)
{
    ANS_LOGD("sts AniSetBadgeNumber call, BadgeNumber: %{public}lf", badgeNumber);
    int returncode = Notification::NotificationHelper::SetBadgeNumber(static_cast<int32_t>(badgeNumber));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts AniSetBadgeNumber error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("sts AniSetBadgeNumber end");
}

void AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_double badgeNumber)
{
    ANS_LOGD("AniSetBadgeNumberByBundle call, badgeNumber: %{public}lf", badgeNumber);
    int returncode = ERR_OK;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
        returncode = Notification::NotificationHelper::SetBadgeNumberByBundle(option,
            static_cast<int32_t>(badgeNumber));
    } else {
        ANS_LOGE("sts AniSetBadgeNumberByBundle ERROR_INTERNAL_ERROR");
        OHOS::NotificationSts::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts AniSetBadgeNumberByBundle error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetBadgeNumberByBundle end");
}
}
}