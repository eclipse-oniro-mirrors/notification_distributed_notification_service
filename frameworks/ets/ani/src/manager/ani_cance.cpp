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

void AniCancelWithId(ani_env* env, ani_int id)
{
    ANS_LOGD("AniCancelWithId call,id : %{public}d", id);
    int returncode = Notification::NotificationHelper::CancelNotification(id);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithId -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithId notifications end");
}

void AniCancelWithIdLabel(ani_env* env, ani_int id, ani_string label)
{
    ANS_LOGD("AniCancelWithIdLabel call");
    std::string labelStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, label, labelStr)) {
        NotificationSts::ThrowStsErroWithLog(env, "Label parse failed!");
        return;
    }
    
    ANS_LOGD("Cancel by label id:%{public}d label:%{public}s", id, labelStr.c_str());
    int returncode = Notification::NotificationHelper::CancelNotification(labelStr, id);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithIdLabel -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithIdLabel end");
}

void AniCancelWithBundle(ani_env* env, ani_object bundleObj, ani_int id)
{
    ANS_LOGD("AniCancelWithBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, option)) {
         NotificationSts::ThrowStsErroWithLog(env, "BundleOption parse failed!");
        return;
    }
    
    ANS_LOGD("Cancel by bundle:%{public}s id:%{public}d",
        option.GetBundleName().c_str(), id);
    int returncode = Notification::NotificationHelper::CancelAsBundle(option, id);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithBundle -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithBundle end");
}
} // namespace NotificationManagerSts
} // namespace OHOS