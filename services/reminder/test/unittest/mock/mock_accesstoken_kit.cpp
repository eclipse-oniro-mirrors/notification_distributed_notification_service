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

#include "mock_accesstoken_kit.h"

using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Notification {
namespace {
ATokenTypeEnum g_mockGetTokenTypeFlagRet = ATokenTypeEnum::TOKEN_INVALID;
DlpType g_mockDlpType = DlpType::DLP_COMMON;
ATokenAplEnum g_mockApl = ATokenAplEnum::APL_NORMAL;
bool g_isSystemApp = true;
bool g_mockVerfyPermisson = true;
}

void MockAccesstokenKit::MockGetTokenTypeFlag(ATokenTypeEnum mockRet)
{
    g_mockGetTokenTypeFlagRet = mockRet;
}
void MockAccesstokenKit::MockDlpType(DlpType mockRet)
{
    g_mockDlpType = mockRet;
}
void MockAccesstokenKit::MockApl(ATokenAplEnum mockRet)
{
    g_mockApl = mockRet;
}

void MockAccesstokenKit::MockIsVerfyPermisson(bool isVerify)
{
    g_mockVerfyPermisson = isVerify;
}
void MockAccesstokenKit::MockIsSystemApp(bool isSystemApp)
{
    g_isSystemApp = isSystemApp;
}
}
}
namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!Notification::g_mockVerfyPermisson) {
        return PERMISSION_DENIED;
    }

    if (tokenID == Notification::NON_NATIVE_TOKEN) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return Notification::g_mockGetTokenTypeFlagRet;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    info.dlpType = Notification::g_mockDlpType;
    info.apl = Notification::g_mockApl;
    return 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS