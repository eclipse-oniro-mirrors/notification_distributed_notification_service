/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "bundle_manager_helper.h"

#include "mock_bundle_manager_helper.h"
#include "ans_ut_constant.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {

bool g_getBundle = true;
bool g_systemBundle = false;
int32_t g_bundleHelperResult = 0;
std::vector<NotificationBundleOption> g_installedBundles;
bool g_isAncoApp = false;

void MockBundleManager::MockBundleInterfaceResult(const int32_t result)
{
    g_bundleHelperResult = result;
}

void MockBundleManager::MockInstallBundle(const NotificationBundleOption& bundleOption)
{
    if (bundleOption.GetUid() > 0) {
        g_installedBundles.push_back(bundleOption);
    }
}

void MockBundleManager::MockUninstallBundle(const NotificationBundleOption& bundleOption)
{
    for (auto iter = g_installedBundles.begin(); iter != g_installedBundles.end();) {
        if (iter->GetUid() == bundleOption.GetUid()) {
            g_installedBundles.erase(iter);
        } else {
            iter++;
        }
    }
}

void MockBundleManager::MockClearInstalledBundle()
{
    g_installedBundles.clear();
}

void MockBundleManager::MockBundleRseult(bool result)
{
    g_getBundle = result;
}

void MockBundleManager::MockSystemBundle(bool systemBundle)
{
    g_systemBundle = systemBundle;
}

void MockBundleManager::MockIsAncoApp(bool isAncoApp)
{
    g_isAncoApp = isAncoApp;
}

void BundleManagerHelper::OnRemoteDied(const wptr<IRemoteObject> &object)
{}

std::string BundleManagerHelper::GetBundleNameByUid(int uid)
{
    return (uid == NON_BUNDLE_NAME_UID) ? "" : "bundleName";
}

int BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    if (userId == 0 || bundle == "testBundleName") {
        return -1;
    } else {
        return NON_SYSTEM_APP_UID;
    }
}

int32_t BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId,
    const int32_t appIndex)
{
    return NON_SYSTEM_APP_UID;
}

bool BundleManagerHelper::IsSystemApp(int uid)
{
    return (uid == SYSTEM_APP_UID || uid == NON_BUNDLE_NAME_UID);
}

bool BundleManagerHelper::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption)
{
    return true;
}

bool BundleManagerHelper::GetBundleInfoByBundleName(
    const std::string bundle, const int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    return true;
}

void BundleManagerHelper::Connect()
{}

void BundleManagerHelper::Disconnect()
{}

#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
bool BundleManagerHelper::GetDistributedNotificationEnabled(const std::string &bundleName, const int userId)
{
    return true;
}
#endif

bool BundleManagerHelper::CheckApiCompatibility(const std::string &bundleName, const int32_t &uid)
{
    return true;
}

ErrCode BundleManagerHelper::GetAllBundleOption(std::vector<NotificationBundleOption>& bundleOptions, int32_t userId)
{
    if (g_bundleHelperResult == 0) {
        bundleOptions = g_installedBundles;
    }
    return g_bundleHelperResult;
}

ErrCode BundleManagerHelper::GetAllBundleInfo(std::map<std::string, sptr<NotificationBundleOption>>& bundleOptions,
    int32_t userId)
{
    return ERR_OK;
}

bool BundleManagerHelper::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    int32_t userId, AppExecFwk::BundleInfo &bundleInfo)
{
    return true;
}

bool BundleManagerHelper::GetBundleInfos(
    const AppExecFwk::BundleFlag flag, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId)
{
    return true;
}

int32_t BundleManagerHelper::GetAppIndexByUid(const int32_t uid)
{
    if (uid == 100 * 200000 + 1000 + 0) return 0;
    if (uid == 100 * 200000 + 1000 + 1) return 1;
    if (uid == 100 * 200000 + 1000 + 2) return 2;
    return 0;
}

bool BundleManagerHelper::GetBundleInfoV9(const std::string bundle, const int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, const int32_t userId)
{
    return g_getBundle;
}

ErrCode BundleManagerHelper::GetApplicationInfo(const std::string &bundleName, int32_t flags, int32_t userId,
    AppExecFwk::ApplicationInfo &appInfo)
{
    return ERR_OK;
}

bool BundleManagerHelper::CheckSystemApp(const std::string& bundleName, int32_t userId)
{
    return g_systemBundle;
}

ErrCode BundleManagerHelper::GetBundleResourceInfo(const std::string &bundleName,
    AppExecFwk::BundleResourceInfo &bundleResourceInfo, const int32_t appIndex)
{
    return g_bundleHelperResult;
}

bool BundleManagerHelper::QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos,
    int32_t userId)
{
    return true;
}

bool BundleManagerHelper::CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption)
{
    return true;
}

bool BundleManagerHelper::CheckCurrentUserIdApp(const std::string &bundleName, const int32_t uid, const int32_t userId)
{
    return true;
}

bool BundleManagerHelper::IsAncoApp(const std::string &bundleName, int32_t uid)
{
    return g_isAncoApp;
}

bool BundleManagerHelper::GetCloneAppIndexes(
    const std::string& bundleName, std::vector<int32_t>& appIndexes, int32_t userId)
{
    return true;
}

bool BundleManagerHelper::GetCloneBundleInfo(
    const std::string& bundleName, int32_t flag, int32_t appIndex, AppExecFwk::BundleInfo& bundleInfo, int32_t userId)
{
    return true;
}

std::string BundleManagerHelper::GetBundleLabel(const std::string& bundleName)
{
    return std::string();
}

bool BundleManagerHelper::IsAtomicServiceByBundle(const std::string& bundleName, const int32_t userId)
{
    return false;
}

bool BundleManagerHelper::GetSandboxDataDir(
    const std::string &bundleName, int32_t appIndex, std::string &sandboxDataDir)
{
    if (bundleName.empty()) {
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
