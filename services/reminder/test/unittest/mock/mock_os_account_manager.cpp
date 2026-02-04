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

#include "mock_os_account_manager.h"

#include "os_account_manager.h"

namespace OHOS {
static int32_t g_mockGetOsAccountLocalIdFromUidRet = 0;
static int32_t g_mockGetOsAccountLocalIdFromUidUserId = 100;

namespace Notification {
void MockOsAccountManager::MockGetOsAccountLocalIdFromUid(const int32_t userId, const int32_t ret)
{
    g_mockGetOsAccountLocalIdFromUidUserId = userId;
    g_mockGetOsAccountLocalIdFromUidRet = ret;
}
}

namespace AccountSA {
ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    id = g_mockGetOsAccountLocalIdFromUidUserId;
    return g_mockGetOsAccountLocalIdFromUidRet;
}
}
} // namespace OHOS