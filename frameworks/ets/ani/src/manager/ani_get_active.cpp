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
#include "ani_get_active.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_request.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
ani_long AniGetActiveNotificationCount(ani_env *env)
{
    ANS_LOGD("sts GetActiveNotificationCount call");
    uint64_t num = 0;
    int returncode = OHOS::Notification::NotificationHelper::GetActiveNotificationNums(num);
    ANS_LOGD("sts GetActiveNotificationCount end, num: %{public}llu", num);
    ani_long retNum = static_cast<ani_long>(num);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetActiveNotificationCount error, errorCode: %{public}d", externalCode);
        return 0;
    }
    return retNum;
}

ani_object AniGetAllActiveNotifications(ani_env *env)
{
    ANS_LOGD("sts AniGetAllActiveNotifications call");
    std::vector<sptr<NotificationSts::NotificationSts>> notifications;
    int returncode = OHOS::Notification::NotificationHelper::GetAllActiveNotifications(notifications);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetAllActiveNotifications error, errorCode: %{public}d", externalCode);
        return nullptr;
    }
    ani_object arrayRequestObj;
    if (notifications.size() == 0) {
        arrayRequestObj = NotificationSts::newArrayClass(env, 0);
    } else {
        arrayRequestObj = NotificationSts::GetAniNotificationRequestArrayByNotifocations(env, notifications);
    }
    if (arrayRequestObj == nullptr) {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetAllActiveNotifications  ERROR_INTERNAL_ERROR");
    }
    ANS_LOGD("sts AniGetAllActiveNotifications end");
    return arrayRequestObj;
}

ani_object AniGetActiveNotifications(ani_env *env)
{
    ANS_LOGD("sts AniGetActiveNotifications call");
    std::vector<sptr<NotificationSts::NotificationRequest>> requests;
    int returncode = OHOS::Notification::NotificationHelper::GetActiveNotifications(requests);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetActiveNotifications error, errorCode: %{public}d", externalCode);
        return nullptr;
    }
    ani_object arrayRequestObj;
    if (requests.size() == 0) {
        arrayRequestObj = NotificationSts::newArrayClass(env, 0);
    } else {
        arrayRequestObj = NotificationSts::GetAniNotificationRequestArray(env, requests);
    }
    if (arrayRequestObj == nullptr) {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetActiveNotifications ERROR_INTERNAL_ERROR");
    }
    ANS_LOGD("sts AniGetActiveNotifications end");
    return arrayRequestObj;
}

ani_object AniGetActiveNotificationByFilter(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniGetActiveNotificationByFilter call");
    Notification::LiveViewFilter filter;
    if (!OHOS::NotificationSts::UnWarpNotificationFilter(env, obj, filter)) {
        NotificationSts::ThrowStsErroWithMsg(env, "sts UnWarpNotificationFilter ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    sptr<OHOS::Notification::NotificationRequest> notificationRequest = nullptr;
    int returncode = Notification::NotificationHelper::GetActiveNotificationByFilter(filter, notificationRequest);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetActiveNotificationByFilter error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }

    ani_object requestObj = nullptr;
    ani_class requestCls;
    if (!NotificationSts::WarpNotificationRequest(env, notificationRequest.GetRefPtr(), requestCls, requestObj)
        || requestObj == nullptr) {
        NotificationSts::ThrowStsErroWithMsg(env, "sts UnWarpNotificationFilter ERROR_INTERNAL_ERROR");
        ANS_LOGE("AniGetActiveNotificationByFilter WarpNotificationRequest faild");
        return nullptr;
    }
    ANS_LOGD("AniGetActiveNotificationByFilter end");
    return requestObj;
}
} // namespace NotificationManagerSts
} // namespace OHOS