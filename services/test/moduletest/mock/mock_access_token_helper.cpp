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

namespace OHOS {
namespace Notification {
bool AccessTokenHelper::VerifyCallerPermission(
    const Security::AccessToken::AccessTokenID &tokenCaller, const std::string &permission)
{
    return true;
}

bool AccessTokenHelper::VerifyNativeToken(const Security::AccessToken::AccessTokenID &callerToken)
{
    return true;
}

bool AccessTokenHelper::IsSystemApp()
{
    return true;
}

bool AccessTokenHelper::IsDlpHap(const Security::AccessToken::AccessTokenID &callerToken)
{
    return false;
}
}  // namespace Notification
}  // namespace OHOS