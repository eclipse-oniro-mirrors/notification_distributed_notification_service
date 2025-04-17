/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "base_publish_process.h"

#include "access_token_helper.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "ans_permission_def.h"
#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {

ErrCode BasePublishProcess::PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    if (!request->IsRemoveAllowed()) {
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
        }
    }
    return ERR_OK;
}

ErrCode BasePublishProcess::CommonPublishCheck(const sptr<NotificationRequest> &request)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_2, EventBranchId::BRANCH_1);
    if (request->GetReceiverUserId() != SUBSCRIBE_USER_INIT) {
        if (!AccessTokenHelper::IsSystemApp()) {
            message.Message("Not SystemApp");
            message.ErrorCode(ERR_ANS_NON_SYSTEM_APP);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            return ERR_ANS_NON_SYSTEM_APP;
        }
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)
            && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SEND_NOTIFICATION_CROSS_USER)) {
            message.BranchId(EventBranchId::BRANCH_3);
            message.Message("CheckPermission denied");
            message.ErrorCode(ERR_ANS_NON_SYSTEM_APP);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            return ERR_ANS_PERMISSION_DENIED;
        }
    }
    return ERR_OK;
}

ErrCode BasePublishProcess::CommonPublishProcess(const sptr<NotificationRequest> &request)
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenHelper::IsDlpHap(callerToken)) {
        ANS_LOGE("DLP hap not allowed to send notifications");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_2, EventBranchId::BRANCH_5)
            .ErrorCode(ERR_ANS_DLP_HAP).Message("CommonPublishProcess failed");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_DLP_HAP;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
