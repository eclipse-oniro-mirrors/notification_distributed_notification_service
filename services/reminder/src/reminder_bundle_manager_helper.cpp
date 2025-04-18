/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "reminder_bundle_manager_helper.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "ans_const_define.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
ReminderBundleManagerHelper::ReminderBundleManagerHelper()
{
    deathRecipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&ReminderBundleManagerHelper::OnRemoteDied, this, std::placeholders::_1));
    if (deathRecipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

ReminderBundleManagerHelper::~ReminderBundleManagerHelper()
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

void ReminderBundleManagerHelper::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

void ReminderBundleManagerHelper::Connect()
{
    if (bundleMgr_ != nullptr) {
        return;
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        return;
    }

    bundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
    }
}

void ReminderBundleManagerHelper::Disconnect()
{
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        bundleMgr_ = nullptr;
    }
}

std::string ReminderBundleManagerHelper::GetBundleNameByUid(int32_t uid)
{
    std::string bundle;

    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        bundleMgr_->GetNameForUid(uid, bundle);
        IPCSkeleton::SetCallingIdentity(identity);
    }

    return bundle;
}

int32_t ReminderBundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    int32_t uid = -1;

    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        uid = bundleMgr_->GetUidByBundleName(bundle, userId);
        if (uid < 0) {
            ANS_LOGW("get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
        }
        IPCSkeleton::SetCallingIdentity(identity);
    }

    return uid;
}

bool ReminderBundleManagerHelper::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);

    Connect();

    if (bundleMgr_ == nullptr) {
        return false;
    }
    int32_t callingUserId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(userId, callingUserId);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool ret = bundleMgr_->GetBundleInfo(bundleName, flag, bundleInfo, callingUserId);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

int32_t ReminderBundleManagerHelper::GetAppIndexByUid(const int32_t uid)
{
    int32_t appIndex = 0;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (nullptr == bundleMgr_) {
        return appIndex;
    }
    std::string bundleName;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr_->GetNameAndIndexForUid(uid, bundleName, appIndex);
    IPCSkeleton::SetCallingIdentity(identity);
    return appIndex;
}

}  // namespace Notification
}  // namespace OHOS
