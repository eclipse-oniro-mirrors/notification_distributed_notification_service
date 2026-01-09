
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

#include "bundle_service_connector.h"

#include "ans_log_wrapper.h"

#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace Notification {
namespace Infra {
BundleServiceConnector::BundleServiceConnector()
{
    deathRecipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&BundleServiceConnector::OnRemoteDied, this, std::placeholders::_1));
    if (deathRecipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

BundleServiceConnector::~BundleServiceConnector()
{
    std::lock_guard<ffrt::mutex> lock(connectionMutex_);
    Disconnect();
}

sptr<AppExecFwk::IBundleMgr> BundleServiceConnector::GetBundleManager()
{
    std::string bundle;

    std::lock_guard<ffrt::mutex> lock(connectionMutex_);
    if (bundleMgr_ != nullptr) {
        return bundleMgr_;
    }

    Connect();
    return bundleMgr_;
}

void BundleServiceConnector::Connect()
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

    return;
}

void BundleServiceConnector::Disconnect()
{
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        bundleMgr_ = nullptr;
    }
    return;
}

void BundleServiceConnector::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    std::lock_guard<ffrt::mutex> lock(connectionMutex_);
    Disconnect();
    return;
}
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS
