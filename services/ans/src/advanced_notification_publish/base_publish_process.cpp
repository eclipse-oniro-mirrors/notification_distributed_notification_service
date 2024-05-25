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

namespace OHOS {
namespace Notification {
namespace {
const std::string NOTIFICATION_CES_CHECK_SA_PERMISSION = "notification.ces.check.sa.permission";
} // namespace

std::string BasePublishProcess::supportCheckSaPermission_ = "false";

BasePublishProcess::BasePublishProcess()
{
    supportCheckSaPermission_ = OHOS::system::GetParameter(NOTIFICATION_CES_CHECK_SA_PERMISSION, "false");
}

ErrCode BasePublishProcess::PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    if (!request->IsRemoveAllowed()) {
        if (!CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
        }
    }
    return ERR_OK;
}

bool BasePublishProcess::CheckPermission(const std::string &permission)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (supportCheckSaPermission_.compare("true") != 0) {
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (isSubsystem) {
            return true;
        }
    }
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool result = AccessTokenHelper::VerifyCallerPermission(tokenCaller, permission);
    if (!result) {
        ANS_LOGE("Permission denied");
    }
    return result;
}

ErrCode BasePublishProcess::CommonPublishCheck(const sptr<NotificationRequest> &request)
{
    if (request->GetReceiverUserId() != SUBSCRIBE_USER_INIT) {
        if (!AccessTokenHelper::IsSystemApp()) {
            return ERR_ANS_NON_SYSTEM_APP;
        }
        if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
        return ERR_ANS_DLP_HAP;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
