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

#include "iaccount_manager_impl.h"

#include <vector>
#include "errors.h"
#include "ipc_skeleton.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "os_account_manager.h"

namespace OHOS {
namespace Notification {
namespace Infra {
ErrCode IAccountManagerImpl::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &userId)
{
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (ret != ERR_OK) {
        ANS_LOGE("Get user id from uid %{public}d, %{public}d failed.", uid, ret);
    }
    ANS_LOGD("Get user id from uid %{public}d, %{public}d failed.", uid, userId);
    return ret;
}

int32_t IAccountManagerImpl::GetOsAccountLocalIdFromUid(const int32_t uid)
{
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (ret != ERR_OK) {
        ANS_LOGE("Get user id from uid %{public}d, %{public}d failed.", uid, ret);
    }
    ANS_LOGD("Get user id from uid %{public}d, %{public}d failed.", uid, userId);
    return userId;
}

ErrCode IAccountManagerImpl::GetCurrentCallingUserId(int32_t &userId)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    if (ret != ERR_OK) {
        ANS_LOGE("Get userId failed, callingUid = <%{public}d>, code is %{public}d", callingUid, ret);
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGD("Get userId Success, callingUid = <%{public}d> userId = <%{public}d>", callingUid, userId);
    return ERR_OK;
}

ErrCode IAccountManagerImpl::GetCurrentActiveUserId(int32_t &id)
{
#ifdef NOTIFICATION_MULTI_FOREGROUND_USER
    ANS_LOGE("multi foreground user is not supported this function");
#endif
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to get userid %{public}d.", ret);
    }
    return ret;
}

int32_t IAccountManagerImpl::GetCurrentActiveUserIdWithDefault(int32_t defaultUserId)
{
#ifdef NOTIFICATION_MULTI_FOREGROUND_USER
    ANS_LOGE("multi foreground user is not supported this function");
#endif
    int32_t userId = defaultUserId;
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to get userid with default %{public}d, %{public}d.", defaultUserId, ret);
        return defaultUserId;
    }
    return userId;
}

ErrCode IAccountManagerImpl::GetAllOsAccount(std::vector<int32_t> &userIds)
{
    std::vector<AccountSA::OsAccountInfo> accounts;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accounts);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to get all account %{public}d.", ret);
        return ret;
    }
    for (auto item : accounts) {
        userIds.emplace_back(item.GetLocalId());
    }
    return ret;
}

ErrCode IAccountManagerImpl::GetAllActiveOsAccount(std::vector<int32_t> &userIds)
{
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(userIds);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to get all active account %{public}d", ret);
    }
    return ret;
}

bool IAccountManagerImpl::CheckUserIdExists(const int32_t &userId, bool defaultValue)
{
    bool isAccountExists = defaultValue;
    int32_t ret = OHOS::AccountSA::OsAccountManager::IsOsAccountExists(userId, isAccountExists);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call check userid %{public}d, %{public}d.", userId, ret);
        return defaultValue;
    }
    ANS_LOGD("Call check userid %{public}d, %{public}d.", userId, isAccountExists);
    return isAccountExists;
}

bool IAccountManagerImpl::IsSystemAccount(int32_t userId)
{
    return userId >= AccountSA::Constants::START_USER_ID && userId <= AccountSA::Constants::MAX_USER_ID;
}

ErrCode IAccountManagerImpl::GetOsAccountPrivateStatus(bool &isPrivate)
{
    int32_t userId = 0;
    ErrCode queryRes = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (queryRes != ERR_OK) {
        ANS_LOGE("GetForegroundOsAccountLocalId fail, queryRes: %{public}d", queryRes);
        return queryRes;
    }
    AccountSA::OsAccountType type;
    queryRes = AccountSA::OsAccountManager::GetOsAccountType(userId, type);
    if (queryRes != ERR_OK) {
        ANS_LOGE("GetOsAccountTypef fail, queryRes: %{public}d", queryRes);
        return queryRes;
    }
    ANS_LOGI("GetOsAccountTypef, type: %{public}d", type);
    isPrivate = type == AccountSA::OsAccountType::PRIVATE;
    return queryRes;
}

bool IAccountManagerImpl::IsOsAccountVerified(int32_t userId, bool defaultValue)
{
    bool verified = defaultValue;
    ErrCode result = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(userId, verified);
    if (result != ERR_OK) {
        ANS_LOGE("Account varified fail %{public}d.", userId);
    }
    return verified;
}

ErrCode IAccountManagerImpl::GetForegroundUserIds(std::vector<int32_t> &foregroundUserIds)
{
    std::vector<AccountSA::ForegroundOsAccount> accounts;
    auto result = AccountSA::OsAccountManager::GetForegroundOsAccounts(accounts);
    if (result != ERR_OK) {
        return result;
    }
    for (const auto &account : accounts) {
        foregroundUserIds.push_back(account.localId);
    }
    return ERR_OK;
}
} // Infra
} // Notification
} // OHOS
