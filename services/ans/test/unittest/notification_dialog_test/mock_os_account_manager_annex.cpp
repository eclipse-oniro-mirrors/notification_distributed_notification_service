/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

namespace {
int32_t g_mockId = 100; // default id when there is no os_account part
bool g_mockQueryForgroundOsAccountRet = true;
bool g_mockGetOsAccountLocalIdFromUidRet = true;
int32_t g_mockIdForGetOsAccountLocalIdFromUid = 100;
bool g_mockOsAccountExists = true;
std::vector<OHOS::AccountSA::OsAccountInfo> g_mockOsAccountInfos;
}

void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase)
{
    g_mockQueryForgroundOsAccountRet = mockRet;
    switch (mockCase) {
        case 1: {
            g_mockId = 101; // 101 mockcase1
            break;
        }
        case 2: {
            g_mockId = 0; // 0 mockcase1
            break;
        }
        default: {
            g_mockId = 100; // 100 mockdefault
            break;
        }
    }
}

void MockIsOsAccountExists(bool mockRet)
{
    g_mockOsAccountExists = mockRet;
}

void ResetAccountMock()
{
    g_mockId = 100; // 100 mockId
    g_mockQueryForgroundOsAccountRet = true;
    g_mockGetOsAccountLocalIdFromUidRet = true;
    g_mockIdForGetOsAccountLocalIdFromUid = 100;
    g_mockOsAccountExists = true;
}

void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0)
{
    g_mockGetOsAccountLocalIdFromUidRet = mockRet;
    switch (mockCase) {
        case 1: { // mock for invalid id
            g_mockIdForGetOsAccountLocalIdFromUid = -2; // -2 mock for invalid id
            break;
        }
        case 2: { // mock for system id
            g_mockIdForGetOsAccountLocalIdFromUid = 88; // 88 mock for system id
            break;
        }
        default: {
            g_mockIdForGetOsAccountLocalIdFromUid = 100; // 100 mock for system id
            break;
        }
    }
}

void MockQueryAllCreatedOsAccounts(int32_t userId)
{
    g_mockOsAccountInfos.clear();
    OHOS::AccountSA::OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(userId);
    g_mockOsAccountInfos.push_back(osAccountInfo);
}

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountManager::GetForegroundOsAccountLocalId(int32_t &id)
{
    if (!g_mockQueryForgroundOsAccountRet) {
        return ERR_INVALID_OPERATION;
    }
    id = g_mockId;
    return ERR_OK;
}

ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    id = g_mockIdForGetOsAccountLocalIdFromUid;
    return g_mockGetOsAccountLocalIdFromUidRet ? ERR_OK : ERR_INVALID_OPERATION;
}

ErrCode OsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    isOsAccountExists = g_mockOsAccountExists;
    return ERR_OK;
}

ErrCode OsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    osAccountInfos = g_mockOsAccountInfos;
    return ERR_OK;
}
}  // namespace EventFwk
}  // namespace OHOS