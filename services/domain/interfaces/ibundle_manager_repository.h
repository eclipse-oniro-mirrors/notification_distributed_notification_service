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

#ifndef ANS_IBUNDLE_MANAGER_REPOSITORY_H
#define ANS_IBUNDLE_MANAGER_REPOSITORY_H

#include <string>

namespace OHOS {
namespace Notification {
namespace Domain {
class IBundleManagerRepository {
public:
    virtual ~IBundleManagerRepository() = default;

    /**
     * @brief Obtains the bundle name base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the bundle name.
     */
    std::string GetBundleNameByUid(int32_t uid) = 0;

    /**
     * @brief Check whether the caller is a system application base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the check result.
     */
    bool IsSystemApp(int32_t uid) = 0;

    /**
     * @brief Check API compatibility.
     *
     * @param bundleOption Indicates the bundle option.
     * @return Returns the check result.
     */
    bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption) = 0;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId) = 0;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the app Index.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId, const int32_t appIndex) = 0;

    /**
     * @brief Obtains the bundle info.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param bundleInfo Indicates the bundle info.
     * @return Returns the uid.
     */
    bool GetBundleInfoByBundleName(const std::string bundle, const int32_t userId,
        AppExecFwk::BundleInfo &bundleInfo) = 0;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    /**
     * @brief Check whether the specified bundle has the distributed notification supported.
     *
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
    bool GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId) = 0;
#endif

    /**
     * @brief Check API compatibility.
     *
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the bundle uid.
     * @return Returns the check result.
     */
    bool CheckApiCompatibility(const std::string &bundleName, const int32_t &uid) = 0;

    /**
     * @brief Obtains the app index by uid.
     * @param uid Indicates uid.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    int32_t GetAppIndexByUid(const int32_t uid) = 0;

    /**
     * @brief GetBundleInfoV9.
     * @param bundle bundle name.
     * @param flag query condation.
     * @param bundleInfo bundle info.
     * @param userId userId.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    bool GetBundleInfoV9(const std::string bundle, const int32_t flag,
        AppExecFwk::BundleInfo &bundleInfo, const int32_t userId) = 0;

    /**
     * @brief CheckSystemApp.
     * @param bundleName bundle name.
     * @param userId userId.
     * @return Returns the query result. if systemapp, retrun true.
     */
    bool CheckSystemApp(const std::string& bundleName, int32_t userId) = 0;

    ErrCode GetAllBundleInfo(std::map<std::string, sptr<NotificationBundleOption>>& bundleOptions, int32_t userId) = 0;
    bool QueryExtensionInfos(
        std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos, int32_t userId) = 0;
    bool CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption) = 0;
    std::string GetBundleLabel(const std::string& bundleName) = 0;
    bool CheckCurrentUserIdApp(const std::string &bundleName, const int32_t uid, const int32_t userId) = 0;
    bool GetCloneAppIndexes(const std::string &bundleName, std::vector<int32_t> &appIndexes, int32_t userId) = 0;
    bool GetCloneBundleInfo(const std::string &bundleName, int32_t flag, int32_t appIndex,
        AppExecFwk::BundleInfo& bundleInfo, int32_t userId) = 0;

    bool IsAncoApp(const std::string &bundleName, int32_t uid) = 0;
    bool IsAtomicServiceByBundle(const std::string& bundleName, const int32_t userId) = 0;
};
} // namespace Domain
} // namespace Notification
} // namespace OHOS
#endif
