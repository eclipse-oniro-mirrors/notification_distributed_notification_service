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

#include "inner_errors.h"
#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_request.h"
#include "notification_request.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;

void AniPublish(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object obj)
{
    ANS_LOGD("AniPublish call");
    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, obj, notificationRequest) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationRequest failed");
        NotificationSts::ThrowStsErroWithLog(env, "AniPublish ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = NotificationHelper::PublishNotification(*notificationRequest);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniPublish error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniPublish end");
}

void AniPublishWithId(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object obj,
    ani_double userId)
{
    //NotificationRequest request;
    std::shared_ptr<NotificationRequest> notificationRequest = std::make_shared<NotificationRequest>();
    if (NotificationSts::UnWarpNotificationRequest(env, obj, notificationRequest) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationRequest failed");
        NotificationSts::ThrowStsErroWithLog(env, "AniPublishWithId ERROR_INTERNAL_ERROR");
        return;
    }
    notificationRequest->SetOwnerUserId(static_cast<int32_t>(userId));
    int returncode = NotificationHelper::PublishNotification(*notificationRequest);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniPublishWithId error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniPublishWithId leave");
}
} // namespace NotificationManagerSts
} // namespace OHOS