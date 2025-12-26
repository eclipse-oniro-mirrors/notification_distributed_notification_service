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
#include "ans_status.h"

namespace OHOS {
namespace Notification {

AnsStatus BasePublishProcess::PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    if (!request->IsRemoveAllowed()) {
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
        }
    }
    return AnsStatus();
}

AnsStatus BasePublishProcess::CommonPublishCheck(const sptr<NotificationRequest> &request)
{
    if (request->GetReceiverUserId() != SUBSCRIBE_USER_INIT) {
        if (!AccessTokenHelper::IsSystemApp()) {
            return AnsStatus::NonSystemApp("Not SystemApp", EventSceneId::SCENE_2, EventBranchId::BRANCH_1);
        }
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)
            && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SEND_NOTIFICATION_CROSS_USER)) {
            return AnsStatus::PermissionDeny("CheckPermission denied", EventSceneId::SCENE_2, EventBranchId::BRANCH_3);
        }
    }
    return AnsStatus();
}

AnsStatus BasePublishProcess::CommonPublishProcess(const sptr<NotificationRequest> &request)
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenHelper::IsDlpHap(callerToken)) {
        ANS_LOGE("DLP hap not allowed to send notifications");
        return AnsStatus(ERR_ANS_DLP_HAP, "CommonPublishProcess failed",
            EventSceneId::SCENE_2, EventBranchId::BRANCH_5);
    }
    return AnsStatus();
}
}  // namespace Notification
}  // namespace OHOS
