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

#include "bundle_manager_repository_impl.h"

namespace OHOS {
namespace Notification {
namespace Infra {
constexpr int32_t APP_TYPE_ONE = 1;
constexpr int32_t APP_TYPE_TWO = 2;

std::string BundleManagerRepositoryImpl::GetBundleNameByUid(int32_t uid)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return bundle;
    }

    std::string bundle;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr->GetNameForUid(uid, bundle);
    IPCSkeleton::SetCallingIdentity(identity);

    return bundle;
}

int32_t BundleManagerRepositoryImpl::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    int32_t uid = -1;

    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return uid;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    uid = bundleMgr->GetUidByBundleName(bundle, userId);
    if (uid < 0) {
        ANS_LOGW("get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
    }
    IPCSkeleton::SetCallingIdentity(identity);

    return uid;
}

int32_t BundleManagerRepositoryImpl::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId,
    const int32_t appIndex)
{
    int32_t uid = -1;
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return uid;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    uid = bundleMgr->GetUidByBundleName(bundle, userId, appIndex);
    if (uid < 0) {
        ANS_LOGW("get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
    }
    IPCSkeleton::SetCallingIdentity(identity);

    return uid;
}

bool BundleManagerRepositoryImpl::GetBundleInfoByBundleName(
    const std::string bundle, const int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    bool ret = false;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    ret = bundleMgr->GetBundleInfo(bundle, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
bool BundleManagerRepositoryImpl::GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr != nullptr) {
        AppExecFwk::ApplicationInfo appInfo;
        if (bundleMgr->GetApplicationInfo(
            bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo)) {
            ANS_LOGD("APPLICATION_INFO distributed enabled %{public}d", appInfo.distributedNotificationEnabled);
            return appInfo.distributedNotificationEnabled;
        }
    }

    ANS_LOGD("APPLICATION_INFO distributed enabled is default");
    return DEFAULT_DISTRIBUTED_ENABLE_IN_APPLICATION_INFO;
}
#endif

int32_t BundleManagerRepositoryImpl::GetAppIndexByUid(const int32_t uid)
{
    int32_t appIndex = 0;
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return appIndex;
    }
    std::string bundleName;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr->GetNameAndIndexForUid(uid, bundleName, appIndex);
    IPCSkeleton::SetCallingIdentity(identity);
    return appIndex;
}


bool BundleManagerRepositoryImpl::GetBundleInfoV9(
    const std::string bundle, const int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, const int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = bundleMgr->GetBundleInfoV9(bundle, flag, bundleInfo, userId);
    IPCSkeleton::SetCallingIdentity(identity);
    if (ret != ERR_OK) {
        ANS_LOGE("Bundle failed %{public}s %{public}d %{public}d %{public}d.", bundle.c_str(),
            flag, userId, ret);
        return false;
    }
    return true;
}

ErrCode BundleManagerRepositoryImpl::GetAllBundleInfo(
    std::map<std::string, sptr<NotificationBundleOption>>& bundleOptions, int32_t userId)
{
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    {
        auto bundleMgr = connector_->GetBundleManager();
        if (bundleMgr == nullptr) {
            ANS_LOGE("GetBundleInfo bundle proxy failed.");
            return -1;
        }

        int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        ErrCode result = bundleMgr->GetBundleInfosV9(flags, bundleInfos, userId);
        IPCSkeleton::SetCallingIdentity(identity);
        if (result != ERR_OK) {
            ANS_LOGE("Get installed bundle failed %{public}d.", result);
            return result;
        }
    }
    for (auto& bundle : bundleInfos) {
        if (bundle.applicationInfo.bundleType != AppExecFwk::BundleType::APP ||
            bundle.applicationInfo.codePath == std::to_string(APP_TYPE_ONE) ||
            bundle.applicationInfo.codePath == std::to_string(APP_TYPE_TWO)) {
            ANS_LOGD("Get not app %{public}s", bundle.applicationInfo.bundleName.c_str());
            continue;
        }

        ANS_LOGI("Get bundle %{public}d %{public}s.", bundle.applicationInfo.uid,
            bundle.applicationInfo.bundleName.c_str());
        sptr<NotificationBundleOption> option = new (std::nothrow) NotificationBundleOption(
            bundle.applicationInfo.bundleName, bundle.applicationInfo.uid);
        if (option == nullptr) {
            ANS_LOGE("Get bundle failed.");
            continue;
        }
        std::string key = bundle.applicationInfo.bundleName + std::to_string(bundle.applicationInfo.uid);
        bundleOptions[key] = option;
    }

    ANS_LOGI("Get installed bundle size %{public}zu.", bundleOptions.size());
    return ERR_OK;
}

bool BundleManagerRepositoryImpl::GetCloneAppIndexes(
    const std::string& bundleName, std::vector<int32_t>& appIndexes, int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetBundleInfo bundle proxy failed.");
        return false;
    }

    ErrCode result = 0;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    result = bundleMgr->GetCloneAppIndexes(bundleName, appIndexes, userId);
    IPCSkeleton::SetCallingIdentity(identity);

    if (result != ERR_OK) {
        ANS_LOGE("GetCloneAppIndexes failed %{public}d.", result);
        return false;
    }

    return true;
}

bool BundleManagerRepositoryImpl::GetCloneBundleInfo(
    const std::string& bundleName, int32_t flag, int32_t appIndex, AppExecFwk::BundleInfo& bundleInfo, int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return false;
    }

    ErrCode result = 0;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    result = bundleMgr->GetCloneBundleInfo(bundleName, flag, appIndex, bundleInfo, userId);
    IPCSkeleton::SetCallingIdentity(identity);

    if (result != ERR_OK) {
        ANS_LOGE("GetCloneBundleInfo failed %{public}d.", result);
        return false;
    }

    return true;
}

bool BundleManagerRepositoryImpl::IsSystemApp(int32_t uid)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return false;
    }

    bool isSystemApp = false;
    if (bundleMgr != nullptr) {
        isSystemApp = bundleMgr->CheckIsSystemAppByUid(uid);
    }

    return isSystemApp;
}

bool BundleManagerRepositoryImpl::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos,
    int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return false;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr->QueryExtensionAbilityInfos(AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER,
        userId, extensionInfos);
    IPCSkeleton::SetCallingIdentity(identity);
    return true;
}

bool BundleManagerRepositoryImpl::IsAncoApp(const std::string &bundleName, int32_t uid)
{
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId);
    if (userId == -1 || userId >= DEFAULT_USER_ID) {
        return false;
    }

    userId = ZERO_USERID;
    AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    if (!GetBundleInfoV9(bundleName, flags, bundleInfo, userId)) {
        ANS_LOGW("Get Bundle bundleName %{public}s, %{public}d", bundleName.c_str(), userId);
        return false;
    }

    return bundleInfo.applicationInfo.codePath == std::to_string(APP_TYPE_ONE);
}

bool BundleManagerRepositoryImpl::CheckSystemApp(const std::string& bundleName, int32_t userId)
{
    if (userId == SUBSCRIBE_USER_INIT) {
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    if (!GetBundleInfoV9(bundleName, flags, bundleInfo, userId)) {
        ANS_LOGE("Get installed bundle failed.");
        return false;
    }

    ANS_LOGI("Get installed bundle %{public}s %{public}d.", bundleName.c_str(),
        bundleInfo.applicationInfo.isSystemApp);
    return bundleInfo.applicationInfo.isSystemApp;
}


bool BundleManagerRepositoryImpl::IsAtomicServiceByBundle(const std::string& bundleName, const int32_t userId)
{
    auto flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    AppExecFwk::BundleInfo bundleInfo;
    if (!GetBundleInfoV9(bundleName, flags, bundleInfo, userId)) {
        ANS_LOGE("GetBundleInfoV9 error, bundleName = %{public}s uid = %{public}d", bundleInfo.name.c_str(),
            bundleInfo.uid);
    }
    return bundleInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE;
}

bool BundleManagerRepositoryImpl::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr");
        return false;
    }
    return CheckApiCompatibility(bundleOption->GetBundleName(), bundleOption->GetUid());
}

bool BundleManagerRepositoryImpl::CheckApiCompatibility(const std::string &bundleName, const int32_t &uid)
{
#ifdef ANS_DISABLE_FA_MODEL
    return false;
#endif
    AppExecFwk::BundleInfo bundleInfo;
    int32_t callingUserId;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, callingUserId);
    if (!GetBundleInfoByBundleName(bundleName, callingUserId, bundleInfo)) {
        ANS_LOGE("Failed to GetBundleInfoByBundleName, bundlename = %{public}s",
            bundleName.c_str());
        return false;
    }

    for (auto abilityInfo : bundleInfo.abilityInfos) {
        if (abilityInfo.isStageBasedModel) {
            return false;
        }
    }
    return true;
}

bool BundleManagerRepositoryImpl::CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption)
{
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    auto flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
        | static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)
        | static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY)
        | static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);

    AppExecFwk::BundleInfo bundleInfo;
    if (!GetBundleInfoV9(bundleOption->GetBundleName(), flags, bundleInfo, userId)) {
        ANS_LOGE("GetBundleInfoV9 error, bundleName = %{public}s, userId = %{public}d",
            bundleOption->GetBundleName().c_str(), userId);
        return false;
    }
    if (!AccessTokenHelper::VerifyCallerPermission(
        bundleInfo.applicationInfo.accessTokenId, OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return false;
    }
    
    for (const auto& hapmodule : bundleInfo.hapModuleInfos) {
        for (const auto& extInfo : hapmodule.extensionInfos) {
            if (extInfo.type == AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS
