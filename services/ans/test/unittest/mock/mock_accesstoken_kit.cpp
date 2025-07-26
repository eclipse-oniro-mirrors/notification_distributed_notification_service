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

#include "accesstoken_kit.h"
#include "ans_ut_constant.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Notification {
namespace {
ATokenTypeEnum g_mockGetTokenTypeFlagRet = ATokenTypeEnum::TOKEN_INVALID;
DlpType g_mockDlpType = DlpType::DLP_COMMON;
ATokenAplEnum g_mockApl = ATokenAplEnum::APL_NORMAL;
bool g_mockVerfyPermisson = true;
bool g_isSystemApp = false;
bool g_isAtomicService = false;
}

void MockGetTokenTypeFlag(ATokenTypeEnum mockRet)
{
    g_mockGetTokenTypeFlagRet = mockRet;
}
void MockDlpType(DlpType mockRet)
{
    g_mockDlpType = mockRet;
}
void MockApl(ATokenAplEnum mockRet)
{
    g_mockApl = mockRet;
}

void MockIsVerfyPermisson(bool isVerify)
{
    g_mockVerfyPermisson = isVerify;
}

void MockIsSystemAppByFullTokenID(bool isSystemApp)
{
    g_isSystemApp = isSystemApp;
}

void MockIsAtomicServiceByFullTokenID(bool isAtomicService)
{
    g_isAtomicService = isAtomicService;
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
    return 0;
}

bool AccessTokenKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    return Notification::g_isSystemApp;
}

bool AccessTokenKit::IsAtomicServiceByFullTokenID(uint64_t tokenId)
{
    return Notification::g_isAtomicService;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
