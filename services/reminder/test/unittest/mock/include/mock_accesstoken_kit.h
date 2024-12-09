/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_MOCK_ACCESSTOKEN_KIT_H
#define BASE_NOTIFICATION_MOCK_ACCESSTOKEN_KIT_H

#include "accesstoken_kit.h"
#include "ans_log_wrapper.h"
#include "reminder_ut_constant.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {
class MockAccesstokenKit {
public:
    static void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
    static void MockDlpType(Security::AccessToken::DlpType mockRet);
    static void MockApl(Security::AccessToken::ATokenAplEnum mockRet);
    static void MockIsVerfyPermisson(bool isVerify);
    static void MockIsSystemApp(bool isSystemApp);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_MOCK_ACCESSTOKEN_KIT_H
