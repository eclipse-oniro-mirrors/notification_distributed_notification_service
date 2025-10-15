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
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGD("AniCancelAll -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelAll notifications end");
}

void AniCancelWithId(ani_env* env, ani_int id)
{
    ANS_LOGD("AniCancelWithId call,id : %{public}d", id);
    int returncode = Notification::NotificationHelper::CancelNotification(static_cast<int32_t>(id));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGD("AniCancelWithId -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithId notifications end");
}

void AniCancelWithIdLabel(ani_env* env, ani_int id, ani_string label)
{
    ANS_LOGD("AniCancelWithIdLabel call");
    std::string tempStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, label, tempStr)) {
        NotificationSts::ThrowErrorWithMsg(env, "Label parse failed!");
        return;
    }
    std::string labelStr = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
    ANS_LOGD("Cancel by label id:%{public}d label:%{public}s", id, labelStr.c_str());
    int returncode = Notification::NotificationHelper::CancelNotification(labelStr, static_cast<int32_t>(id));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGD("AniCancelWithIdLabel -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithIdLabel end");
}

void AniCancelWithBundle(ani_env* env, ani_object bundleObj, ani_int id)
{
    ANS_LOGD("AniCancelWithBundle call");
    Notification::NotificationBundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, option)) {
        NotificationSts::ThrowErrorWithMsg(env, "BundleOption parse failed!");
        return;
    }
    
    ANS_LOGD("Cancel by bundle:%{public}s id:%{public}d",
        option.GetBundleName().c_str(), id);
    int returncode = Notification::NotificationHelper::CancelAsBundleWithAgent(option, static_cast<int32_t>(id));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniCancelWithBundle -> error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniCancelWithBundle end");
}

void AniCancelWithIdOptinalLabel(ani_env* env, ani_int id, ani_string label)
{
    ANS_LOGD("sts AniCancelWithIdOptinalLabel call, id:%{public}d", id);
    ani_boolean isUndefined = ANI_FALSE;
    env->Reference_IsUndefined(label, &isUndefined);
    int32_t ret = -1;
    if (isUndefined) {
        ANS_LOGE("sts AniCancelWithIdOptinalLabel the label is undefined");
        ret = Notification::NotificationHelper::CancelNotification(static_cast<int32_t>(id));
    } else {
        std::string tempStr;
        if (ANI_OK != NotificationSts::GetStringByAniString(env, label, tempStr)) {
            OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            ANS_LOGE("sts AniCancelWithIdOptinalLabel ERROR_INTERNAL_ERROR");
            return;
        }
        std::string labelStr = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
        ANS_LOGD("sts AniCancelWithIdOptinalLabel id:%{public}d label:%{public}s", id, labelStr.c_str());
        ret = Notification::NotificationHelper::CancelNotification(labelStr, id);
    }
    if (ret != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(ret);
        ANS_LOGE("sts AniCancelWithIdOptinalLabel error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("sts AniCancelWithIdOptinalLabel end");
}

void AniCancelAsBundle(ani_env *env, ani_int id, ani_string representativeBundle, ani_int userId)
{
    ANS_LOGD("AniCancelAsBundle enter");
    int32_t convertedId = static_cast<int32_t>(id);
    int32_t UserId = static_cast<int32_t>(userId);
    std::string bundleStr;

    if (ANI_OK != NotificationSts::GetStringByAniString(env, representativeBundle, bundleStr)) {
        ANS_LOGE("AniCancelAsBundle:: representativeBundle parse failed!");
        NotificationSts::ThrowErrorWithMsg(env, "representativeBundle parse failed!");
        return;
    }
    ANS_LOGD("AniCancelAsBundle, convertedId: %{public}d, UserId: %{public}d, bundleStr: %{public}s",
        convertedId, UserId, bundleStr.c_str());

    int returncode = Notification::NotificationHelper::CancelAsBundle(convertedId, bundleStr, UserId);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGD("AniCancelAsBundle: CancelAsBundle retern erro. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    ANS_LOGD("AniCancelAsBundle end");
}

void AniCancelAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle, ani_int id)
{
    ANS_LOGD("AniCancelAsBundleWithBundleOption enter");
    int32_t idTest = static_cast<int32_t>(id);
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, representativeBundle, option) != true) {
        ANS_LOGE("AniPublishAsBundleWithBundleOption BundleOption parse failed!");
        NotificationSts::ThrowErrorWithMsg(env, "AniPublishAsBundleWithBundleOption BundleOption parse failed!");
        return;
    }

    ANS_LOGD("AniPublishAsBundleWithBundleOption: bundle %{public}s, uid: %{public}d, id: %{public}d",
        option.GetBundleName().c_str(), option.GetUid(), idTest);

    int returncode =  Notification::NotificationHelper::CancelAsBundle(option, idTest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGD("CancelAsBundle retern error. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    ANS_LOGD("AniCancelAsBundleWithBundleOption end");
}

void AniCancelGroup(ani_env *env, ani_string groupName)
{
    ANS_LOGD("AniCancelGroup enter");

    std::string tempStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, groupName, tempStr)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniCancelGroup: groupName parse failed!");
        return;
    }
    std::string groupNameStr = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
    ANS_LOGD("AniCancelGroup groupNameStr: %{public}s", groupNameStr.c_str());
    int returncode = Notification::NotificationHelper::CancelGroup(groupNameStr);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGD("AniCancelGroup: CancelAsBundle retern erro. returncode: %{public}d, externalCode: %{public}d",
            returncode, externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniCancelGroup end");
}
} // namespace NotificationManagerSts
} // namespace OHOS