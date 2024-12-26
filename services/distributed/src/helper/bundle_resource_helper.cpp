/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "bundle_resource_helper.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {

BundleResourceHelper::BundleResourceHelper()
{
    deathRecipient_ = new (std::nothrow)
        BundleDeathRecipient(std::bind(&BundleResourceHelper::OnRemoteDied, this, std::placeholders::_1));
    if (deathRecipient_ == nullptr) {
        ANS_LOGE("Failed to create BundleDeathRecipient instance");
    }
}

BundleResourceHelper::~BundleResourceHelper()
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

void BundleResourceHelper::Connect()
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

    bundleMgr_ = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
    }
}

void BundleResourceHelper::Disconnect()
{
    if (bundleMgr_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        bundleMgr_ = nullptr;
    }
}

void BundleResourceHelper::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Disconnect();
}

ErrCode BundleResourceHelper::GetBundleInfo(const std::string &bundleName,
    AppExecFwk::BundleResourceInfo &bundleResourceInfo, const int32_t appIndex)
{
    ErrCode result = 0;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (bundleMgr_ == nullptr) {
        ANS_LOGE("GetBundleInfo bundle proxy failed.");
        return -1;
    }
    sptr<AppExecFwk::IBundleResource> bundleResourceProxy = bundleMgr_->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        ANS_LOGE("GetBundleInfo, get bundle resource proxy failed.");
        return -1;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t flag = static_cast<int32_t>(AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    result = bundleResourceProxy->GetBundleResourceInfo(bundleName, flag, bundleResourceInfo, appIndex);
    IPCSkeleton::SetCallingIdentity(identity);
    return result;
}
}
}
