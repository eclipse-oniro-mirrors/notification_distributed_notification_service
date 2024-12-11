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
#include "reminder_ut_constant.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {

bool ReminderAccessTokenHelper::VerifyNativeToken(const Security::AccessToken::AccessTokenID &callerToken)
{
    return callerToken == NATIVE_TOKEN;
}

bool ReminderAccessTokenHelper::IsSystemApp()
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (tokenId == NATIVE_TOKEN) {
        return true;
    }
    return false;
}

}  // namespace Notification
}  // namespace OHOS