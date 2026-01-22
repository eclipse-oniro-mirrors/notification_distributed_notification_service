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

#include "bundle_manager_adapter.h"
#include "iaccount_manager_impl.h"

#include "ans_const_define.h"

namespace OHOS {
namespace Notification {
namespace Infra {

#define IN_PROCESS_CALL(theCall)                                     \
    ([&]() {                                                         \
        std::string identity = IPCSkeleton::ResetCallingIdentity();  \
        auto retVal = theCall;                                       \
        IPCSkeleton::SetCallingIdentity(identity);                   \
        return retVal;                                               \
    }())

#define IN_PROCESS_CALL_WITHOUT_RET(theCall)                         \
    do {                                                             \
        std::string identity = IPCSkeleton::ResetCallingIdentity();  \
        theCall;                                                     \
        IPCSkeleton::SetCallingIdentity(identity);                   \
    } while (0)

constexpr int32_t APP_TYPE_ONE = 1;
constexpr int32_t APP_TYPE_TWO = 2;

bool BundleManagerRepositoryImpl::IsSystemApp(int32_t uid)
{
    bool isSystemApp = false;
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return false;
    }
    isSystemApp = bundleMgr->CheckIsSystemAppByUid(uid);
    return isSystemApp;
}

bool BundleManagerRepositoryImpl::CheckSystemApp(const std::string& bundleName, int32_t userId)
{
    if (userId == SUBSCRIBE_USER_INIT) {
        IAccountManagerImpl::GetCurrentActiveUserId(userId);
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

std::string BundleManagerRepositoryImpl::GetBundleNameByUid(int32_t uid)
{
    std::string bundle;
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return "";
    }

    if (IN_PROCESS_CALL(bundleMgr->GetNameForUid(uid, bundle)) != ERR_OK) {
        ANS_LOGE("Get bundleName failed.");
        return "";
    }
    return bundle;
}

int32_t BundleManagerRepositoryImpl::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    return GetDefaultUidByBundleName(bundle, userId, -1);
}

int32_t BundleManagerRepositoryImpl::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId,
    const int32_t appIndex)
{
    int32_t uid = -1;

    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return uid;
    }
    uid = (appIndex < 0)
        ? IN_PROCESS_CALL(bundleMgr->GetUidByBundleName(bundle, userId))
        : IN_PROCESS_CALL(bundleMgr->GetUidByBundleName(bundle, userId, appIndex));
    if (uid < 0) {
        ANS_LOGW("Get invalid uid of bundle %{public}s in userId %{public}d", bundle.c_str(), userId);
    }

    return uid;
}

int32_t BundleManagerRepositoryImpl::GetAppIndexByUid(const int32_t uid)
{
    int32_t appIndex = 0;
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return appIndex;
    }
    std::string bundleName;
    if (IN_PROCESS_CALL(bundleMgr->GetNameAndIndexForUid(uid, bundleName, appIndex)) != ERR_OK) {
        ANS_LOGE("Get appIndex failed.");
    }
    return appIndex;
}

bool BundleManagerRepositoryImpl::GetBundleInfoByBundleName(
    const std::string bundle, const int32_t userId, NotificationBundleManagerInfo &bundleInfo)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    AppExecFwk::BundleInfo externalBundle;
    if (!IN_PROCESS_CALL(bundleMgr->GetBundleInfo(
        bundle, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, externalBundle, userId))) {
        ANS_LOGE("Get bundleInfo failed.");
        return false;
    }
    ConvertBundleInfo(externalBundle, bundleInfo);
    return true;
}

bool BundleManagerRepositoryImpl::GetBundleInfo(const std::string &bundleName, const NotificationBundleManagerFlag flag,
    int32_t uid, NotificationBundleManagerInfo &bundleInfo)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    int32_t callingUserId;
    IAccountManagerImpl::GetOsAccountLocalIdFromUid(uid, callingUserId);

    AppExecFwk::BundleInfo externalBundle;
    if (!IN_PROCESS_CALL(bundleMgr->GetBundleInfo(
        bundleName, static_cast<AppExecFwk::BundleFlag>(flag), externalBundle, callingUserId))) {
        ANS_LOGE("Get bundleInfo failed.");
        return false;
    }
    ConvertBundleInfo(externalBundle, bundleInfo);
    return true;
}

bool BundleManagerRepositoryImpl::GetBundleInfos(const NotificationBundleManagerFlag flag,
    std::vector<NotificationBundleManagerInfo> &bundleInfos, int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    std::vector<AppExecFwk::BundleInfo> externalBundles;
    if (!IN_PROCESS_CALL(bundleMgr->GetBundleInfos(
        static_cast<AppExecFwk::BundleFlag>(flag), externalBundles, userId))) {
        ANS_LOGE("Get bundleInfos failed.");
        return false;
    }
    ConvertBundleInfo(externalBundles, bundleInfos);
    return true;
}


bool BundleManagerRepositoryImpl::GetBundleInfoV9(
    const std::string bundle, const int32_t flag,
    NotificationBundleManagerInfo &bundleInfo, const int32_t userId)
{
    AppExecFwk::BundleInfo externalBundle;
    if (!GetBundleInfoV9(bundle, flag, externalBundle, userId)) {
        return false;
    }
    ConvertBundleInfo(externalBundle, bundleInfo);
    return true;
}

bool BundleManagerRepositoryImpl::GetBundleInfoV9(
    const std::string bundle, const int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, const int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    ErrCode ret = IN_PROCESS_CALL(bundleMgr->GetBundleInfoV9(bundle, flag, bundleInfo, userId));
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
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetBundleInfo bundle proxy failed.");
        return -1;
    }

    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    ErrCode result = IN_PROCESS_CALL(bundleMgr->GetBundleInfosV9(flags, bundleInfos, userId));
    if (result != ERR_OK) {
        ANS_LOGE("Get installed bundle failed %{public}d.", result);
        return result;
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

ErrCode BundleManagerRepositoryImpl::GetBundleResourceInfo(const std::string &bundleName,
    AppExecFwk::BundleResourceInfo &bundleResourceInfo, const int32_t appIndex)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return -1;
    }
    sptr<AppExecFwk::IBundleResource> bundleResourceProxy = bundleMgr->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        ANS_LOGE("Get bundle resource proxy failed.");
        return -1;
    }

    int32_t flag = static_cast<int32_t>(AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<int32_t>(AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    ErrCode result = IN_PROCESS_CALL(
        bundleResourceProxy->GetBundleResourceInfo(bundleName, flag, bundleResourceInfo, appIndex));
    return result;
}

std::string BundleManagerRepositoryImpl::GetBundleLabel(const std::string& bundleName)
{
    AppExecFwk::BundleResourceInfo bundleResourceInfo = {};
    int32_t result = GetBundleResourceInfo(bundleName, bundleResourceInfo, 0);
    if (result != ERR_OK) {
        return "";
    }
    return bundleResourceInfo.label;
}

bool BundleManagerRepositoryImpl::GetCloneAppIndexes(
    const std::string& bundleName, std::vector<int32_t>& appIndexes, int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return false;
    }

    ErrCode result = IN_PROCESS_CALL(bundleMgr->GetCloneAppIndexes(bundleName, appIndexes, userId));
    if (result != ERR_OK) {
        ANS_LOGE("GetCloneAppIndexes failed %{public}d.", result);
        return false;
    }

    return true;
}

bool BundleManagerRepositoryImpl::GetCloneBundleInfo(const std::string& bundleName, int32_t flag, int32_t appIndex,
    NotificationBundleManagerInfo &bundleInfo, int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return false;
    }

    AppExecFwk::BundleInfo externalBundle;
    ErrCode result = IN_PROCESS_CALL(bundleMgr->GetCloneBundleInfo(bundleName, flag, appIndex, externalBundle, userId));
    if (result != ERR_OK) {
        ANS_LOGE("GetCloneBundleInfo failed %{public}d.", result);
        return false;
    }

    ConvertBundleInfo(externalBundle, bundleInfo);
    return true;
}

bool BundleManagerRepositoryImpl::CheckCurrentUserIdApp(
    const std::string &bundleName, const int32_t uid, const int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    if (!GetBundleInfoV9(bundleName, flags, bundleInfo, userId)) {
        ANS_LOGW("Get Bundle bundleName %{public}s, %{public}d", bundleName.c_str(), userId);
        return false;
    }

    return bundleInfo.uid == uid;
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
    NotificationBundleManagerInfo bundleInfo;
    int32_t callingUserId;
    IAccountManagerImpl::GetOsAccountLocalIdFromUid(uid, callingUserId);
    if (!GetBundleInfoByBundleName(bundleName, callingUserId, bundleInfo)) {
        ANS_LOGE("Failed to GetBundleInfoByBundleName, bundlename = %{public}s", bundleName.c_str());
        return false;
    }

    return !bundleInfo.isStageBasedModel;
}

bool BundleManagerRepositoryImpl::IsAncoApp(const std::string &bundleName, int32_t uid)
{
    int32_t userId = -1;
    IAccountManagerImpl::GetOsAccountLocalIdFromUid(uid, userId);
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

ErrCode BundleManagerRepositoryImpl::GetApplicationInfo(const std::string &bundleName, int32_t flags,
    int32_t userId, AppExecFwk::ApplicationInfo &appInfo)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        ANS_LOGE("GetCloneBundleInfo bundle proxy failed.");
        return -1;
    }

    ErrCode result = IN_PROCESS_CALL(bundleMgr->GetApplicationInfoV9(bundleName, flags, userId, appInfo));
    return result;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
bool BundleManagerRepositoryImpl::GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId)
{
    auto bundleMgr = connector_->GetBundleManager();
    if (bundleMgr == nullptr) {
        return DEFAULT_DISTRIBUTED_ENABLE_IN_APPLICATION_INFO;
    }

    AppExecFwk::ApplicationInfo appInfo;
    if (bundleMgr->GetApplicationInfo(
        bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo)) {
        ANS_LOGD("APPLICATION_INFO distributed enabled %{public}d", appInfo.distributedNotificationEnabled);
        return appInfo.distributedNotificationEnabled;
    }

    ANS_LOGD("APPLICATION_INFO distributed enabled is default");
    return DEFAULT_DISTRIBUTED_ENABLE_IN_APPLICATION_INFO;
}
#endif

void BundleManagerRepositoryImpl::ConvertBundleInfo(const AppExecFwk::BundleInfo &externalBundleInfo,
    NotificationBundleManagerInfo &bundleInfo)
{
    bundleInfo.bundleName = externalBundleInfo.name;
    bundleInfo.uid = externalBundleInfo.uid;
    bundleInfo.applicationInfo.allowEnableNotification = externalBundleInfo.applicationInfo.allowEnableNotification;
    bundleInfo.applicationInfo.isSystemApp = externalBundleInfo.applicationInfo.isSystemApp;
    bundleInfo.applicationInfo.appIndex = externalBundleInfo.applicationInfo.appIndex;
    bundleInfo.applicationInfo.accessTokenId = externalBundleInfo.applicationInfo.accessTokenId;
    bundleInfo.applicationInfo.label = externalBundleInfo.applicationInfo.label;
    bundleInfo.applicationInfo.bundleName = externalBundleInfo.applicationInfo.bundleName;
    bundleInfo.applicationInfo.installSource = externalBundleInfo.applicationInfo.installSource;
    for (auto abilityInfo : externalBundleInfo.abilityInfos) {
        if (abilityInfo.isStageBasedModel) {
            bundleInfo.isStageBasedModel = true;
        }
    }
    return;
}

void BundleManagerRepositoryImpl::ConvertBundleInfo(const std::vector<AppExecFwk::BundleInfo> &externalBundleInfos,
    std::vector<NotificationBundleManagerInfo> &bundleInfos)
{
    bundleInfos.clear();
    int32_t size = externalBundleInfos.size();
    bundleInfos.reserve(externalBundleInfos.size());
    for (const auto& externalInfo : externalBundleInfos) {
        NotificationBundleManagerInfo info;
        ConvertBundleInfo(externalInfo, info);
        bundleInfos.push_back(std::move(info));
    }
    return;
}
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS
