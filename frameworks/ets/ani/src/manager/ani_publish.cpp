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
#include "ani_publish.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_bundle_option.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_request.h"
#include "notification_request.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;

void AniPublish(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniPublish call");
    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, obj, notificationRequest) != ANI_OK) {
        ANS_LOGE("AniPublish UnWarpNotificationRequest failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniPublish ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = NotificationHelper::PublishNotification(*notificationRequest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniPublish end");
}

void AniPublishWithId(ani_env *env, ani_object obj, ani_int userId)
{
    ANS_LOGD("AniPublishWithId start");
    //NotificationRequest request;
    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, obj, notificationRequest) != ANI_OK) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniPublishWithId ERROR_INTERNAL_ERROR");
        return;
    }
    notificationRequest->SetOwnerUserId(userId);
    int returncode = NotificationHelper::PublishNotification(*notificationRequest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniPublishWithId error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniPublishWithId end");
}

void AniPublishAsBundle(ani_env *env, ani_object request, ani_string representativeBundle, ani_int userId)
{
    ANS_LOGD("AniPublishAsBundle enter");
    std::string bundleStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, representativeBundle, bundleStr)) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniPublishAsBundle ERROR_INTERNAL_ERROR");
        return;
    }

    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, request, notificationRequest) != ANI_OK) {
        ANS_LOGE("AniPublishAsBundle failed");
        NotificationSts::ThrowStsErroWithMsg(env, "AniPublishAsBundle ERROR_INTERNAL_ERROR");
        return;
    }
    notificationRequest->SetOwnerUserId(userId);
    notificationRequest->SetOwnerBundleName(bundleStr);
    int returncode =  NotificationHelper::PublishNotification(*notificationRequest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniPublishAsBundle: PublishNotificationerror, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    ANS_LOGD("AniPublishAsBundle end");
}

void AniPublishAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle, ani_object request)
{
    ANS_LOGE("AniPublishAsBundleWithBundleOption enter");
    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, request, notificationRequest) != ANI_OK) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniPublishAsBundleWithBundleOption ERROR_INTERNAL_ERROR");
        return;
    }

    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, representativeBundle, option) != true) {
        NotificationSts::ThrowStsErroWithMsg(env, "UnwrapBundleOption ERROR_INTERNAL_ERROR");
        return;
    }

    ANS_LOGD("AniPublishAsBundleWithBundleOption: bundle %{public}s  uid: %{public}d",
        option.GetBundleName().c_str(), option.GetUid());
    notificationRequest->SetOwnerBundleName(option.GetBundleName());
    notificationRequest->SetOwnerUid(option.GetUid());
    notificationRequest->SetIsAgentNotification(true);

    int returncode = NotificationHelper::PublishNotification(*notificationRequest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniPublishAsBundleWithBundleOption error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniPublishAsBundleWithBundleOption end");
}
} // namespace NotificationManagerSts
} // namespace OHOS