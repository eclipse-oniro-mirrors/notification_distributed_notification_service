/*
 * @Author: wangkailong wangkailong6@huawei.com
 * @Date: 2022-11-08 10:44:55
 * @LastEditors: wangkailong wangkailong6@huawei.com
 * @LastEditTime: 2022-11-10 11:57:12
 * @FilePath: /distributed_notification_service/services/ans/test/unittest/mock_accesstoken_kit.cpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
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
#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Notification {
namespace {
ATokenTypeEnum g_mockGetTokenTypeFlagRet = ATokenTypeEnum::TOKEN_INVALID;
}

void MockGetTokenTypeFlag(ATokenTypeEnum mockRet)
{
    g_mockGetTokenTypeFlagRet = mockRet;
}
}
}
namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    return PERMISSION_GRANTED;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return Notification::g_mockGetTokenTypeFlagRet;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    return 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
