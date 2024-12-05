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

#include "reminder_access_token_helper.h"

#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "reminder_notification_inline.cpp"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
bool ReminderAccessTokenHelper::IsSystemApp()
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

bool ReminderAccessTokenHelper::VerifyNativeToken(const AccessTokenID &callerToken)
{
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    return (tokenType == ATokenTypeEnum::TOKEN_NATIVE);
}
}  // namespace Notification
}  // namespace OHOS
