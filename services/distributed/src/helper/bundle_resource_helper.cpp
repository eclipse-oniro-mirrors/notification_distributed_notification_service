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

ErrCode BundleResourceHelper::GetAllBundleInfos(int32_t flags, std::vector<AppExecFwk::BundleInfo> &bundleInfos,
    int32_t userId)
{
    ErrCode result = 0;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (bundleMgr_ == nullptr) {
        ANS_LOGE("GetBundleInfo bundle proxy failed.");
        return -1;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    result = bundleMgr_->GetBundleInfosV9(flags, bundleInfos, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    return result;
}

ErrCode BundleResourceHelper::GetAllInstalledBundles(std::vector<std::string> &bundlesName, int32_t userId)
{
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    ErrCode result = GetAllBundleInfos(flags, bundleInfos, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Get installed bundle failed %{public}d.", result);
        return result;
    }

    for (auto& bundle : bundleInfos) {
        if (bundle.applicationInfo.bundleType != AppExecFwk::BundleType::APP) {
            ANS_LOGD("Get not app %{public}s", bundle.applicationInfo.bundleName.c_str());
            continue;
        }
        if (!bundle.applicationInfo.isSystemApp) {
            ANS_LOGI("Get bundle app %{public}s", bundle.applicationInfo.bundleName.c_str());
            bundlesName.emplace_back(bundle.applicationInfo.bundleName);
        }
    }

    ANS_LOGI("Get installed bundle size %{public}zu.", bundlesName.size());
    return ERR_OK;
}

ErrCode BundleResourceHelper::GetApplicationInfo(const std::string &appName, int32_t flags, int32_t userId,
    AppExecFwk::ApplicationInfo &appInfo)
{
    ErrCode result = 0;
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (bundleMgr_ == nullptr) {
        ANS_LOGE("GetBundleInfo bundle proxy failed.");
        return -1;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    result = bundleMgr_->GetApplicationInfoV9(appName, flags, userId, appInfo);
    IPCSkeleton::SetCallingIdentity(identity);
    return result;
}

bool BundleResourceHelper::CheckSystemApp(const std::string& bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (GetBundleInfoV9(bundleName, userId, bundleInfo) != ERR_OK) {
        return false;
    }
    ANS_LOGI("Get installed bundle %{public}s %{public}d.", bundleName.c_str(),
        bundleInfo.applicationInfo.isSystemApp);
    return bundleInfo.applicationInfo.isSystemApp;
}

ErrCode BundleResourceHelper::GetBundleInfoV9(const std::string& bundleName, int32_t userId,
    AppExecFwk::BundleInfo& bundleInfo)
{
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    std::lock_guard<std::mutex> lock(connectionMutex_);
    Connect();
    if (bundleMgr_ == nullptr) {
        return false;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t result = bundleMgr_->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    if (result != ERR_OK) {
        ANS_LOGW("Get installed bundle %{public}s failed.", bundleName.c_str());
        return result;
    }
    return ERR_OK;
}
}
}
