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

#ifndef ANS_BUNDLE_MANAGER_REPOSITORY_IMPL_H
#define ANS_BUNDLE_MANAGER_REPOSITORY_IMPL_H

#include "ibundle_manager_repository.h"
#include "bundle_service_connector.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class BundleManagerRepositoryImpl : public Domain::IBundleManagerRepository {
public:
    using ConnectorPtr = std::unique_ptr<BundleServiceConnector>;
    
    explicit BundleManagerRepositoryImpl(ConnectorPtr&& connector)
        : connector_(std::move(connector)) {}

    ~BundleManagerRepositoryImpl() override = default;

    /**
     * @brief Obtains the bundle name base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the bundle name.
     */
    std::string GetBundleNameByUid(int32_t uid) override;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId) override;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the app Index.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(
        const std::string &bundle, const int32_t userId, const int32_t appIndex) override;

    /**
     * @brief Obtains the bundle info.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param bundleInfo Indicates the bundle info.
     * @return Returns the uid.
     */
    bool GetBundleInfoByBundleName(const std::string bundle, const int32_t userId,
        AppExecFwk::BundleInfo &bundleInfo) override;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    /**
     * @brief Check whether the specified bundle has the distributed notification supported.
     *
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
   bool GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId) override;
#endif

    /**
     * @brief Obtains the app index by uid.
     * @param uid Indicates uid.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    int32_t GetAppIndexByUid(const int32_t uid) override;

    /**
     * @brief GetBundleInfoV9.
     * @param bundle bundle name.
     * @param flag query condation.
     * @param bundleInfo bundle info.
     * @param userId userId.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    bool GetBundleInfoV9(const std::string bundle, const int32_t flag,
        AppExecFwk::BundleInfo &bundleInfo, const int32_t userId) override;

    ErrCode GetAllBundleInfo(
        std::map<std::string, sptr<NotificationBundleOption>>& bundleOptions, int32_t userId) override;

    bool CheckCurrentUserIdApp(const std::string &bundleName, const int32_t uid, const int32_t userId) override;

    bool GetCloneAppIndexes(const std::string &bundleName, std::vector<int32_t> &appIndexes, int32_t userId) override;

    bool GetCloneBundleInfo(const std::string &bundleName, int32_t flag, int32_t appIndex,
        AppExecFwk::BundleInfo& bundleInfo, int32_t userId) override;

    bool IsAncoApp(const std::string &bundleName, int32_t uid) override;

    bool IsAtomicServiceByBundle(const std::string& bundleName, const int32_t userId) override;

    /**
     * @brief Check whether the caller is a system application base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the check result.
     */
    bool IsSystemApp(int32_t uid) override;

    bool CheckSystemApp(const std::string& bundleName, int32_t userId) override;

    /**
     * @brief Check API compatibility.
     *
     * @param bundleOption Indicates the bundle option.
     * @return Returns the check result.
     */
    bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption) override;

    bool CheckApiCompatibility(const std::string &bundleName, const int32_t &uid) override;

    bool CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption);
    std::string GetBundleLabel(const std::string& bundleName) override;

    bool QueryExtensionInfos(
        std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos, int32_t userId) override;

private:
    ConnectorPtr connector_;
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
