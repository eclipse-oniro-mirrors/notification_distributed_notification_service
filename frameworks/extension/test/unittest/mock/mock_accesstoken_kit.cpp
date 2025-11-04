/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Notification {
namespace {
bool g_mockVerifyPermission = true;
bool g_mockIsSystemApp = false;
}

void MockIsVerifyPermission(bool isVerify)
{
    g_mockVerifyPermission = isVerify;
}

void MockIsSystemAppByFullTokenID(bool isSystemApp)
{
    g_mockIsSystemApp = isSystemApp;
}
}
}
namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!Notification::g_mockVerifyPermission) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

bool TokenIdKit::IsSystemAppByFullTokenID(uint64_t tokenId)
{
    return Notification::g_mockIsSystemApp;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
