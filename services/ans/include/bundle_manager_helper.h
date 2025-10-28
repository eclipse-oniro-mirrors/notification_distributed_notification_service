/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BUNDLE_MANAGER_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BUNDLE_MANAGER_HELPER_H

#include <memory>
#include <mutex>
#include <string>

#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "notification_bundle_option.h"
#include "refbase.h"
#include "remote_death_recipient.h"
#include "singleton.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
class BundleManagerHelper : public DelayedSingleton<BundleManagerHelper> {
public:
    /**
     * @brief Obtains the bundle name base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the bundle name.
     */
    std::string GetBundleNameByUid(int32_t uid);

    /**
     * @brief Check whether the caller is a system application base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the check result.
     */
    bool IsSystemApp(int32_t uid);

    /**
     * @brief Check API compatibility.
     *
     * @param bundleOption Indicates the bundle option.
     * @return Returns the check result.
     */
    bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId);

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the app Index.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId, const int32_t appIndex);

    /**
     * @brief Obtains the bundle info.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param bundleInfo Indicates the bundle info.
     * @return Returns the uid.
     */
    bool GetBundleInfoByBundleName(const std::string bundle, const int32_t userId, AppExecFwk::BundleInfo &bundleInfo);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    /**
     * @brief Check whether the specified bundle has the distributed notification supported.
     *
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
    bool GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId);
#endif

    /**
     * @brief Obtains bundle info by bundle name.
     *
     * @param bundleName Indicates the bundle name.
     * @param flag Indicates the bundle flag.
     * @param bundleInfo Indicates the bundle info.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
    bool GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
        int32_t userId, AppExecFwk::BundleInfo &bundleInfo);

    /**
     * @brief Obtains BundleInfo of all bundles available in the system through the proxy object.
     * @param flag Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfos is successfully obtained, returns false otherwise.
     */
    bool GetBundleInfos(
        const AppExecFwk::BundleFlag flag, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId);

    /**
     * @brief Obtains the app index by uid.
     * @param uid Indicates uid.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    int32_t GetAppIndexByUid(const int32_t uid);

    /**
     * @brief Check API compatibility.
     *
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the bundle uid.
     * @return Returns the check result.
     */
    bool CheckApiCompatibility(const std::string &bundleName, const int32_t &uid);

    /**
     * @brief GetBundleInfoV9.
     * @param bundle bundle name.
     * @param flag query condation.
     * @param bundleInfo bundle info.
     * @param userId userId.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    bool GetBundleInfoV9(const std::string bundle, const int32_t flag,
        AppExecFwk::BundleInfo &bundleInfo, const int32_t userId);

    /**
     * @brief CheckSystemApp.
     * @param bundleName bundle name.
     * @param userId userId.
     * @return Returns the query result. if systemapp, retrun true.
     */
    bool CheckSystemApp(const std::string& bundleName, int32_t userId);

    /**
     * @brief GetApplicationInfo.
     * @param bundleName bundle name.
     * @param flag query condation.
     * @param userId userId.
     * @param appInfo application info.
     * @return Returns the query result. if succeed, retrun 0.
     */
    ErrCode GetApplicationInfo(const std::string &bundleName, int32_t flags, int32_t userId,
        AppExecFwk::ApplicationInfo &appInfo);

    /**
     * @brief GetBundleResourceInfo.
     * @param bundleName bundle name.
     * @param bundleResourceInfo bundle resource.
     * @param appIndex app index.
     * @return Returns the query result. if succeed, retrun 0.
     */
    ErrCode GetBundleResourceInfo(const std::string &bundleName,
        AppExecFwk::BundleResourceInfo &bundleResourceInfo, const int32_t appIndex);

    ErrCode GetAllBundleInfo(std::map<std::string, sptr<NotificationBundleOption>>& bundleOptions,
        int32_t userId);

    /**
     * Queries extension information by user.
     *
     * @param extensionInfos Indicates the extension information.
     * @param userId Indicates the ID of user.
     * @return Returns true if successful; false otherwise.
     */
    bool QueryExtensionInfos(
        std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos, int32_t userId);
    bool CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption);
    std::string GetBundleLabel(const std::string& bundleName);

    bool IsAncoApp(const std::string &bundleName, int32_t uid);

    /**
     * @brief Determine whether the application is an atomic service based on the bundle name and userId.
     * @param bundleName Bundle name.
     * @param userId User id.
     * @return Returns true if the application is an atomic service; returns false otherwise.
     */
    bool IsAtomicServiceByBundle(const std::string& bundleName, const int32_t userId);
private:
    void Connect();
    void Disconnect();

    void OnRemoteDied(const wptr<IRemoteObject> &object);

private:
    sptr<AppExecFwk::IBundleMgr> bundleMgr_ = nullptr;
    ffrt::mutex connectionMutex_;
    sptr<RemoteDeathRecipient> deathRecipient_ = nullptr;

    DECLARE_DELAYED_SINGLETON(BundleManagerHelper)
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BUNDLE_MANAGER_HELPER_H
