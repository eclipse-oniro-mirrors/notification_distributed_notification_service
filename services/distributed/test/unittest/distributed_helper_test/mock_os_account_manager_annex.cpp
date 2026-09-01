/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "os_account_manager.h"
#include "ans_service_errors.h"

namespace {
bool g_mockGetOsAccountLocalIdFromUidRet = true;
int32_t g_mockIdForGetOsAccountLocalIdFromUid = 0;
}

void MockDistributedGetOsAccountLocalIdFromUid(bool mockRet, int32_t mockId)
{
    g_mockGetOsAccountLocalIdFromUidRet = mockRet;
    g_mockIdForGetOsAccountLocalIdFromUid = mockId;
}

void ResetDistributedAccountMock()
{
    g_mockGetOsAccountLocalIdFromUidRet = true;
    g_mockIdForGetOsAccountLocalIdFromUid = 0;
}

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    id = g_mockIdForGetOsAccountLocalIdFromUid;
    return g_mockGetOsAccountLocalIdFromUidRet ? ERR_OK : OHOS::Notification::ERR_ANS_INNER_INVALID_OPERATION;
}
}  // namespace AccountSA
}  // namespace OHOS
