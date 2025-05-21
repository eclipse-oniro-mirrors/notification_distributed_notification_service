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
#include "ani_cance.h"

#include "inner_errors.h"
#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniCancelAll(ani_env* env)
{
    ANS_LOGD("AniCancelAll notifications call");
    int returncode = Notification::NotificationHelper::CancelAllNotifications();
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelAll -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelAll notifications end");
}

void AniCancelWithId(ani_env* env, ani_double id)
{
    ANS_LOGD("AniCancelWithId call,id : %{public}lf", id);
    int returncode = Notification::NotificationHelper::CancelNotification(static_cast<int32_t>(id));
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithId -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithId notifications end");
}

void AniCancelWithIdLabel(ani_env* env, ani_double id, ani_string label)
{
    ANS_LOGD("AniCancelWithIdLabel call");
    std::string labelStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, label, labelStr)) {
        NotificationSts::ThrowStsErroWithMsg(env, "Label parse failed!");
        return;
    }
    
    ANS_LOGD("Cancel by label id:%{public}lf label:%{public}s", id, labelStr.c_str());
    int returncode = Notification::NotificationHelper::CancelNotification(labelStr, static_cast<int32_t>(id));
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithIdLabel -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithIdLabel end");
}

void AniCancelWithBundle(ani_env* env, ani_object bundleObj, ani_double id)
{
    ANS_LOGD("AniCancelWithBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, option)) {
        NotificationSts::ThrowStsErroWithMsg(env, "BundleOption parse failed!");
        return;
    }
    
    ANS_LOGD("Cancel by bundle:%{public}s id:%{public}lf",
        option.GetBundleName().c_str(), id);
    int returncode = Notification::NotificationHelper::CancelAsBundle(option, static_cast<int32_t>(id));
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithBundle -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithBundle end");
}

void AniCancelWithIdOptinalLabel(ani_env* env, ani_double id, ani_string label)
{
    ANS_LOGD("sts AniCancelWithIdOptinalLabel call, id:%{public}lf", id);
    ani_boolean isUndefined = ANI_FALSE;
    env->Reference_IsUndefined(label, &isUndefined);
    int32_t ret = -1;
    if (isUndefined) {
        ANS_LOGE("sts AniCancelWithIdOptinalLabel the label is undefined");
        ret = Notification::NotificationHelper::CancelNotification(static_cast<int32_t>(id));
    } else {
        std::string labelStr;
        if (ANI_OK != NotificationSts::GetStringByAniString(env, label, labelStr)) {
            OHOS::AbilityRuntime::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            ANS_LOGE("sts AniCancelWithIdOptinalLabel ERROR_INTERNAL_ERROR");
            return;
        }
        ANS_LOGD("sts AniCancelWithIdOptinalLabel id:%{public}lf label:%{public}s", id, labelStr.c_str());
        ret = Notification::NotificationHelper::CancelNotification(labelStr, id);
    }
    int externalCode = CJSystemapi::Notification::ErrorToExternal(ret);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("sts AniCancelWithIdOptinalLabel error, errorCode: %{public}d", externalCode);
        return;
    }
    ANS_LOGD("sts AniCancelWithIdOptinalLabel end, externalCode: %{public}d", externalCode);
}
} // namespace NotificationManagerSts
} // namespace OHOS