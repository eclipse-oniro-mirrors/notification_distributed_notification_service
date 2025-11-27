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
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
ErrCode OsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &userId)
{
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (ret != ERR_OK) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_1)
            .Message("Get userId failed, uid = " + std::to_string(uid) + " ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Get userId failed, uid = <%{public}d>, code is %{public}d", uid, ret);
        return ret;
    }
    ANS_LOGD("Get userId Success, uid = <%{public}d> userId = <%{public}d>", uid, userId);
    return ret;
}

ErrCode OsAccountManagerHelper::GetCurrentCallingUserId(int32_t &userId)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    if (ret != ERR_OK) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_2)
            .Message("Get userId failed, callingUid = " + std::to_string(callingUid) +
            " ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Get userId failed, callingUid = <%{public}d>, code is %{public}d", callingUid, ret);
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGD("Get userId Success, callingUid = <%{public}d> userId = <%{public}d>", callingUid, userId);
    return ERR_OK;
}

ErrCode OsAccountManagerHelper::GetCurrentActiveUserId(int32_t &id)
{
#ifdef NOTIFICATION_MULTI_FOREGROUND_USER
    ANS_LOGE("multi foreground user is not supported this function");
#endif
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (ret != ERR_OK) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_4)
            .Message("Get foreground os account failed ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Failed to call OsAccountManager::GetForegroundOsAccountLocalId, code is %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountManagerHelper::GetAllOsAccount(std::vector<int32_t> &userIds)
{
    std::vector<AccountSA::OsAccountInfo> accounts;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accounts);
    if (ret != ERR_OK) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_3)
            .Message("Get all userId failed ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
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
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_4)
            .Message("Get all active failed ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Failed to call OsAccountManager::QueryActiveOsAccountIds, code is %{public}d", ret);
    }
    return ret;
}

bool OsAccountManagerHelper::CheckUserExists(const int32_t &userId)
{
    bool isAccountExists = false;
    int32_t ret = OHOS::AccountSA::OsAccountManager::IsOsAccountExists(userId, isAccountExists);
    if (ret != ERR_OK) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_5)
            .Message("Get all exist failed ret " + std::to_string(ret));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Failed to call OsAccountManager::IsOsAccountExists, code is %{public}d", ret);
        return false;
    }
    ANS_LOGD("Call IsOsAccountExists Success, user = %{public}d userExists = %{public}d", userId, isAccountExists);
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

ErrCode OsAccountManagerHelper::GetOsAccountPrivateStatus(bool &isPrivate)
{
    int32_t userId = 0;
    ErrCode querryRes = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (querryRes != ERR_OK) {
        ANS_LOGE("GetForegroundOsAccountLocalId fail, querryRes: %{public}d", querryRes);
        return querryRes;
    }
    AccountSA::OsAccountType type;
    querryRes = AccountSA::OsAccountManager::GetOsAccountType(userId, type);
    if (querryRes != ERR_OK) {
        ANS_LOGE("GetOsAccountTypef fail, querryRes: %{public}d", querryRes);
        return querryRes;
    }
    ANS_LOGI("GetOsAccountTypef, type: %{public}d", type);
    isPrivate = type == AccountSA::OsAccountType::PRIVATE;
    return querryRes;
}
}
}
