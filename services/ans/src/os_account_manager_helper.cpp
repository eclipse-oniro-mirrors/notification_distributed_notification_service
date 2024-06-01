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
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "os_account_manager_helper.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include <vector>

namespace OHOS {
namespace Notification {
ErrCode OsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id)
{
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, id);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call OsAccountManager::GetOsAccountLocalIdFromUid, code is %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountManagerHelper::GetCurrentCallingUserId(int32_t &id)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, id);
    if (ret != ERR_OK) {
        ANS_LOGD("Get userId failed, callingUid = <%{public}d>", callingUid);
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGD("Get userId succeeded, callingUid = <%{public}d> userId = <%{public}d>", callingUid, id);
    return ERR_OK;
}

ErrCode OsAccountManagerHelper::GetCurrentActiveUserId(int32_t &id)
{
    std::vector<int> activeUserId;
    int32_t ret = GetAllActiveOsAccount(activeUserId);
    if (activeUserId.size() > 0) {
        id = activeUserId[0];
    }
    return ret;
}

ErrCode OsAccountManagerHelper::GetAllOsAccount(std::vector<int32_t> &userIds)
{
    std::vector<AccountSA::OsAccountInfo> accounts;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accounts);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call OsAccountManager::QueryAllCreatedOsAccounts, code is %{public}d", ret);
        return ret;
    }
    for (auto item : accounts) {
        userIds.emplace_back(item.GetLocalId());
    }
    return ret;
}

ErrCode OsAccountManagerHelper::GetAllActiveOsAccount(std::vector<int32_t> &userIds)
{
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call OsAccountManager::QueryActiveOsAccountIds, code is %{public}d", ret);
    }
    return ret;
}

bool OsAccountManagerHelper::CheckUserExists(const int32_t &userId)
{
    bool isAccountExists = false;
    int32_t ret = OHOS::AccountSA::OsAccountManager::IsOsAccountExists(userId, isAccountExists);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call OsAccountManager::IsOsAccountExists, code is %{public}d", ret);
    }
    return isAccountExists;
}

OsAccountManagerHelper &OsAccountManagerHelper::GetInstance()
{
    return DelayedRefSingleton<OsAccountManagerHelper>::GetInstance();
}

bool OsAccountManagerHelper::IsSystemAccount(int32_t userId)
{
    return userId >= AccountSA::Constants::START_USER_ID && userId <= AccountSA::Constants::MAX_USER_ID;
}
}
}