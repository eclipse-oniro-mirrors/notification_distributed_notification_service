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

#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"

namespace OHOS {
namespace Notification {
ErrCode OsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    return AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, id);
}

ErrCode OsAccountManagerHelper::GetCurrentCallingUserId(int32_t &id)
{
    return AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), id);
}

ErrCode OsAccountManagerHelper::GetCurrentActiveUserId(int32_t &id)
{
    std::vector<int> activeUserId;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);
    if (activeUserId.size() > 0) {
        id = activeUserId[0];
        return ret;
    }
    return ret;
}

bool OsAccountManagerHelper::CheckUserExists(const int32_t &userId)
{
    bool isAccountExists = false;
    OHOS::AccountSA::OsAccountManager::IsOsAccountExists(userId, isAccountExists);
    return isAccountExists;
}

OsAccountManagerHelper &OsAccountManagerHelper::GetInstance()
{
    return DelayedRefSingleton<OsAccountManagerHelper>::GetInstance();
}

}
}