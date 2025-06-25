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
#include "ani_do_not_disturb_date.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"
#include "sts_request.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetDoNotDisturbDate(ani_env *env, ani_object date)
{
    ANS_LOGD("AniSetDoNotDisturbDate enter");
    Notification::NotificationDoNotDisturbDate doNotDisturbDate;
    if (NotificationSts::UnWarpNotificationDoNotDisturbDate(env, date, doNotDisturbDate)) {
        ANS_LOGE("AniSetDoNotDisturbDate UnWarpNotificationDoNotDisturbDate ERROR_INTERNAL_ERROR");
        NotificationSts::ThrowStsErroWithMsg(env, "UnWarpNotificationDoNotDisturbDate ERROR_INTERNAL_ERROR");
        return;
    }

    int returncode = Notification::NotificationHelper::SetDoNotDisturbDate(doNotDisturbDate);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("SetDoNotDisturbDate error. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetDoNotDisturbDate end");
}

void AniSetDoNotDisturbDateWithId(ani_env *env, ani_object date, ani_double userId)
{
    ANS_LOGD("AniSetDoNotDisturbDateWithId enter");
    Notification::NotificationDoNotDisturbDate doNotDisturbDate;
    if (NotificationSts::UnWarpNotificationDoNotDisturbDate(env, date, doNotDisturbDate)) {
        ANS_LOGE("AniSetDoNotDisturbDateWithId UnWarpNotificationDoNotDisturbDate ERROR_INTERNAL_ERROR");
        NotificationSts::ThrowStsErroWithMsg(env, "UnWarpNotificationDoNotDisturbDate ERROR_INTERNAL_ERROR");
        return;
    }

    const int32_t id = static_cast<int32_t>(userId);
    int returncode = Notification::NotificationHelper::SetDoNotDisturbDate(id, doNotDisturbDate);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("SetDoNotDisturbDate erro. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    ANS_LOGD("AniSetDoNotDisturbDateWithId end");
}

ani_object AniGetDoNotDisturbDate(ani_env *env)
{
    ani_object data = nullptr;
    Notification::NotificationDoNotDisturbDate doNotDisturbDate;

    ANS_LOGD("AniGetDoNotDisturbDate enter");
    int returncode = Notification::NotificationHelper::GetDoNotDisturbDate(doNotDisturbDate);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetDoNotDisturbDate retern erro. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return data;
    }

    auto datePtr = std::make_shared<Notification::NotificationDoNotDisturbDate>(doNotDisturbDate);
    if (NotificationSts::WarpNotificationDoNotDisturbDate(env, datePtr, data) == false) {
        ANS_LOGE("WarpNotificationDoNotDisturbDate faild");
        NotificationSts::ThrowStsErroWithMsg(env, "AniGetDoNotDisturbDate ERROR_INTERNAL_ERROR");
    }

    ANS_LOGD("AniGetDoNotDisturbDate end");
    return data;
}

ani_object AniGetDoNotDisturbDateWithId(ani_env *env, ani_double userId)
{
    ani_object data = nullptr;
    Notification::NotificationDoNotDisturbDate doNotDisturbDate;

    ANS_LOGD("AniGetDoNotDisturbDateWithId enter");
    
    const int32_t id = static_cast<int32_t>(userId);
    int returncode = Notification::NotificationHelper::GetDoNotDisturbDate(id, doNotDisturbDate);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetDoNotDisturbDate erro. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return data;
    }

    auto datePtr = std::make_shared<Notification::NotificationDoNotDisturbDate>(doNotDisturbDate);
    if (NotificationSts::WarpNotificationDoNotDisturbDate(env, datePtr, data) == false) {
        ANS_LOGE("AniGetDoNotDisturbDateWithId WarpNotificationDoNotDisturbDate faild");
    }

    ANS_LOGD("AniGetDoNotDisturbDateWithId end");
    return data;
}

ani_boolean AniIsSupportDoNotDisturbMode(ani_env *env)
{
    bool supportDoNotDisturbMode = false;
    ANS_LOGD("AniIsSupportDoNotDisturbMode enter");
    int returncode = Notification::NotificationHelper::DoesSupportDoNotDisturbMode(supportDoNotDisturbMode);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("DoesSupportDoNotDisturbMode error. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return ANI_FALSE;
    }
    ANS_LOGD("DoesSupportDoNotDisturbMode returncode: %{public}d", supportDoNotDisturbMode);
    ANS_LOGD("AniIsSupportDoNotDisturbMode end");
    return NotificationSts::BoolToAniBoolean(supportDoNotDisturbMode);
}

} // namespace NotificationManagerSts
} // namespace OHOS