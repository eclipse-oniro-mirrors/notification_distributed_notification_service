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
namespace {
int32_t g_mockGetForegroundOsAccountLocalId = 0;
}

namespace Notification {
void MockOsAccountManager::MockGetForegroundOsAccountLocalId(const int32_t id)
{
    g_mockGetForegroundOsAccountLocalId = id;
}
}

namespace AccountSA {
ErrCode OsAccountManager::GetForegroundOsAccountLocalId(int32_t& id)
{
    id = g_mockGetForegroundOsAccountLocalId;
    return ERR_OK;
}
}
} // namespace OHOS