// Local copy of mock_bundle_manager_helper.cpp for the extension subscription test target.
// The three methods GetBundleResourceInfo / GetDefaultUidByBundleName(3-arg) / GetAppIndexByUid
// are intentionally removed here: the test file provides its own strong overrides with
// test-specific semantics (icon data injection and clone uid/appIndex mapping).
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

#include "iremote_object.h"
#include "message_parcel.h"

#include "mock_bundle_manager_helper.h"
#include "ans_ut_constant.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "mock_bundle_mgr.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {

bool g_isNonBundleName = false;
void MockIsNonBundleName(bool isNonBundleName)
{
    g_isNonBundleName = isNonBundleName;
}

bool g_getBundle = true;
bool g_systemBundle = false;
int32_t g_bundleHelperResult = 0;
std::string g_bundleIconData;
std::vector<NotificationBundleOption> g_installedBundles;
bool g_isAncoApp = false;

void MockBundleManager::MockBundleInterfaceResult(const int32_t result)
{
    g_bundleHelperResult = result;
}

void MockBundleManager::MockBundleIconData(const std::string &iconData)
{
    g_bundleIconData = iconData;
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
    if (g_isNonBundleName || uid == NON_BUNDLE_NAME_UID) {
        return "";
    }
    return "bundleName";
}

int BundleManagerHelper::GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId)
{
    if (userId <= 0 || bundle == "testBundleName") {
        return -1;
    } else {
        return NON_SYSTEM_APP_UID;
    }
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
{
    if (bundleMgr_ != nullptr) {
        return;
    }
    // Wiring a BundleMgrProxy instance connects the service flows to the
    // BundleMgrProxy method mocks in mock_bundle_mgr.cpp (QueryExtensionAbilityInfos
    // populates extension infos, GetUidByBundleName/GetBundleInfo etc.), while
    // avoiding the real BrokerRegistration IPC against the version-skewed system
    // image (which trips the CFI cross-DSO check of the test binary).
    class LocalMockRemoteObject : public OHOS::IRemoteObject {
    public:
        LocalMockRemoteObject() : IRemoteObject(u"extension_subscription_test_mock") {}
        ~LocalMockRemoteObject() override {}

        int32_t GetObjectRefCount() override
        {
            return 0;
        }

        int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
        {
            return 0;
        }

        bool IsProxyObject() const override
        {
            return false;
        }

        bool CheckObjectLegality() const override
        {
            return true;
        }

        bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
        {
            return true;
        }

        bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
        {
            return true;
        }

        bool Marshalling(Parcel &parcel) const override
        {
            return true;
        }

        sptr<IRemoteBroker> AsInterface() override
        {
            return nullptr;
        }

        int Dump(int fd, const std::vector<std::u16string> &args) override
        {
            return 0;
        }
    };
    sptr<IRemoteObject> object = new (std::nothrow) LocalMockRemoteObject();
    bundleMgr_ = new (std::nothrow) AppExecFwk::BundleMgrProxy(object);
}

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
bool BundleManagerHelper::GetBundleInfos(
    const AppExecFwk::BundleFlag flag, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId)
{
    return true;
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
bool BundleManagerHelper::CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption)
{
    if (&g_isNeedHapModuleInfos != nullptr) {
        return g_isNeedHapModuleInfos;
    }
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
