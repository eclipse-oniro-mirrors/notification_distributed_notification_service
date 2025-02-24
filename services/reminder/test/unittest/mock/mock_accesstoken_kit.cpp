/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "mock_accesstoken_kit.h"

#include "tokenid_kit.h"
#include "accesstoken_kit.h"

namespace OHOS::Notification {
namespace {
int32_t g_mockTokenTypeFlag = static_cast<int32_t>(Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID);
bool g_mockVerfyPermisson = true;
bool g_isSystemApp = true;
}

void MockAccesstokenKit::MockGetTokenTypeFlag(const int32_t flag)
{
    g_mockTokenTypeFlag = flag;
}

void MockAccesstokenKit::MockIsVerifyPermisson(const bool isVerify)
{
    g_mockVerfyPermisson = isVerify;
}
void MockAccesstokenKit::MockIsSystemApp(const bool isSystemApp)
{
    g_isSystemApp = isSystemApp;
}
}

namespace OHOS::Security::AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    return Notification::g_mockVerfyPermisson ? PERMISSION_GRANTED : PERMISSION_DENIED;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return static_cast<ATokenTypeEnum>(Notification::g_mockTokenTypeFlag);
}

bool TokenIdKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    return Notification::g_isSystemApp;
}
} // namespace OHOS::Security::AccessToken
