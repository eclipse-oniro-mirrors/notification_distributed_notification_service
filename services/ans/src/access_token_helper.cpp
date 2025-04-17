/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "access_token_helper.h"

#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "tokenid_kit.h"
#include "notification_analytics_util.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
namespace {
const std::string NOTIFICATION_ANS_CHECK_SA_PERMISSION = "notification.ces.check.sa.permission";
} // namespace

std::string AccessTokenHelper::supportCheckSaPermission_ = "non-initilization";

bool AccessTokenHelper::VerifyCallerPermission(
    const AccessTokenID &tokenCaller, const std::string &permission)
{
    int result = AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    return (result == PERMISSION_GRANTED);
}

bool AccessTokenHelper::VerifyNativeToken(const AccessTokenID &callerToken)
{
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    return (tokenType == ATokenTypeEnum::TOKEN_NATIVE);
}

bool AccessTokenHelper::IsSystemApp()
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (type == ATokenTypeEnum::TOKEN_HAP) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            return true;
        }
    }
    return false;
}

bool AccessTokenHelper::IsDlpHap(const AccessTokenID &callerToken)
{
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (type == ATokenTypeEnum::TOKEN_HAP) {
        HapTokenInfo info;
        AccessTokenKit::GetHapTokenInfo(callerToken, info);
        if (info.dlpType == DlpType::DLP_READ || info.dlpType == DlpType::DLP_FULL_CONTROL) {
            return true;
        }
    }
    return false;
}

bool AccessTokenHelper::VerifyShellToken(const AccessTokenID &callerToken)
{
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    return (tokenType == ATokenTypeEnum::TOKEN_SHELL);
}

bool AccessTokenHelper::CheckPermission(const std::string &permission)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    bool result = VerifyCallerPermission(tokenCaller, permission);
    if (!result) {
        ANS_LOGE("CheckPermission failed %{public}s, %{public}d, %{public}d",
            permission.c_str(), callingUid, callingPid);
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
