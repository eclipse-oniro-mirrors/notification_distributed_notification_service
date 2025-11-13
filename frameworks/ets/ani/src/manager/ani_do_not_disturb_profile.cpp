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
#include "ani_do_not_disturb_profile.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "sts_disturb_mode.h"
#include "sts_bundle_option.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniAddDoNotDisturbProfile(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniAddDoNotDisturbProfile call");
    int returncode = 0;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    if (NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, profiles)) {
        returncode = Notification::NotificationHelper::AddDoNotDisturbProfiles(profiles);
    } else {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniAddDoNotDisturbProfile failed : ERROR_INTERNAL_ERROR");
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniAddDoNotDisturbProfile error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniAddDoNotDisturbProfile end");
}

void AniRemoveDoNotDisturbProfile(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniRemoveDoNotDisturbProfile call");
    int returncode = 0;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    if (NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, profiles)) {
        returncode = Notification::NotificationHelper::RemoveDoNotDisturbProfiles(profiles);
    } else {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniRemoveDoNotDisturbProfile failed : ERROR_INTERNAL_ERROR");
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniRemoveDoNotDisturbProfile error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniRemoveDoNotDisturbProfile end");
}

ani_object AniGetDoNotDisturbProfile(ani_env *env, ani_long id)
{
    ani_object profile;
    ANS_LOGD("AniGetDoNotDisturbProfile enter");

    sptr<NotificationDoNotDisturbProfile> doNotDisturbProfile = new (std::nothrow) NotificationDoNotDisturbProfile();
    if (doNotDisturbProfile == nullptr) {
        ANS_LOGE("Failed to create NotificationDoNotDisturbProfile.");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return nullptr;
    }

    ANS_LOGD("AniGetDoNotDisturbProfile: idTest: %{public}" PRId64, id);
    int returncode = Notification::NotificationHelper::GetDoNotDisturbProfile(id, doNotDisturbProfile);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetDoNotDisturbProfile error, errorCode: %{public}d, returncode: %{public}d",
            externalCode, returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    if (!NotificationSts::WrapDoNotDisturbProfile(env, doNotDisturbProfile, profile)) {
        ANS_LOGE("AniGetDoNotDisturbProfile WrapDoNotDisturbProfile failed");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return nullptr;
    }

    ANS_LOGD("AniGetDoNotDisturbProfile end");
    return profile;
}
}
}