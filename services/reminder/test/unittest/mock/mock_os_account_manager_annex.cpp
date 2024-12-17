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
#include "mock_os_account_manager.h"

namespace OHOS {
const uint8_t MOCK_CASE_INVALID_ID = 1;
const uint8_t MOCK_CASE_SYSTEM_ID = 2;
int32_t g_mockId = 100; // default id when there is no os_account part
bool g_mockQueryForgroundOsAccountRet = true;
bool g_mockGetOsAccountLocalIdFromUidRet = true;
int32_t g_mockIdForGetOsAccountLocalIdFromUid = 100;
bool g_mockOsAccountExists = true;

void MockOsAccountManager::MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase)
{
    g_mockQueryForgroundOsAccountRet = mockRet;
    switch (mockCase) {
        case 1: {
            g_mockId = 101; // 101 mockcase1
            break;
        }
        default: {
            g_mockId = 100; // 100 mockdefault
            break;
        }
    }
}

void MockOsAccountManager::MockIsOsAccountExists(bool mockRet)
{
    g_mockOsAccountExists = mockRet;
}

void MockOsAccountManager::ResetAccountMock()
{
    g_mockId = 100; // 100 mockId
    g_mockQueryForgroundOsAccountRet = true;
    g_mockGetOsAccountLocalIdFromUidRet = true;
    g_mockIdForGetOsAccountLocalIdFromUid = 100; // 100 mockId
    g_mockOsAccountExists = true;
}

void MockOsAccountManager::MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase)
{
    g_mockGetOsAccountLocalIdFromUidRet = mockRet;
    switch (mockCase) {
        case MOCK_CASE_INVALID_ID: { // mock for invalid id
            g_mockIdForGetOsAccountLocalIdFromUid = -2; // -2 mock for invalid id
            break;
        }
        case MOCK_CASE_SYSTEM_ID: { // mock for system id
            g_mockIdForGetOsAccountLocalIdFromUid = 88; // 88 mock for system id
            break;
        }
        default: {
            g_mockIdForGetOsAccountLocalIdFromUid = 100; // 100 mock for system id
            break;
        }
    }
}

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
}  // namespace AccountSA
}  // namespace OHOS