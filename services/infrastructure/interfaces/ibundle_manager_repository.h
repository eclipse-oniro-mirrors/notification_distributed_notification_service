/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_bundle_option.h"
#include "bundle_manager_adapter.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class IBundleManagerRepository {
public:
    virtual ~IBundleManagerRepository() = default;

    /**
     * @brief Check whether the caller is a system application base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the check result.
     */
    virtual bool IsSystemApp(int32_t uid) = 0;

    /**
     * @brief CheckSystemApp.
     * @param bundleName bundle name.
     * @param userId userId.
     * @return Returns the query result. if systemapp, retrun true.
     */
    virtual bool CheckSystemApp(const std::string &bundleName, int32_t userId) = 0;

    /**
     * @brief Obtains the bundle name base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the bundle name.
     */
    virtual std::string GetBundleNameByUid(int32_t uid) = 0;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the uid.
     */
    virtual int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId) = 0;

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param appIndex Indicates the app Index.
     * @return Returns the uid.
     */
    virtual int32_t GetDefaultUidByBundleName(const std::string &bundle,
        const int32_t userId, const int32_t appIndex) = 0;

    /**
     * @brief Obtains the app index by uid.
     * @param uid Indicates uid.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    virtual int32_t GetAppIndexByUid(const int32_t uid) = 0;

    /**
     * @brief Obtains the bundle info.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @param bundleInfo Indicates the bundle info.
     * @return Returns the uid.
     */
    virtual bool GetBundleInfoByBundleName(const std::string bundle, const int32_t userId,
        NotificationBundleManagerInfo &bundleInfo) = 0;

    /**
     * @brief Obtains bundle info by bundle name.
     *
     * @param bundleName Indicates the bundle name.
     * @param flag Indicates the bundle flag.
     * @param bundleInfo Indicates the bundle info.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
    virtual bool GetBundleInfo(const std::string &bundleName, const NotificationBundleManagerFlag flag,
        int32_t userId, NotificationBundleManagerInfo &bundleInfo) = 0;

    /**
     * @brief Obtains BundleInfo of all bundles available in the system through the proxy object.
     * @param flag Indicates the flag used to specify information contained in the BundleInfo that will be returned.
     * @param bundleInfos Indicates all of the obtained BundleInfo objects.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfos is successfully obtained, returns false otherwise.
     */
    virtual bool GetBundleInfos(const NotificationBundleManagerFlag flag,
        std::vector<NotificationBundleManagerInfo> &bundleInfos, int32_t userId) = 0;

    /**
     * @brief GetBundleInfoV9.
     * @param bundle bundle name.
     * @param flag query condation.
     * @param bundleInfo bundle info.
     * @param userId userId.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    virtual bool GetBundleInfoV9(const std::string bundle, const int32_t flag,
        NotificationBundleManagerInfo &bundleInfo, const int32_t userId) = 0;

    virtual ErrCode GetAllBundleInfo(std::map<std::string,
        sptr<NotificationBundleOption>> &bundleOptions, int32_t userId) = 0;

    virtual std::string GetBundleLabel(const std::string& bundleName) = 0;

    virtual bool GetCloneAppIndexes(const std::string &bundleName,
        std::vector<int32_t> &appIndexes, int32_t userId) = 0;

    virtual bool GetCloneBundleInfo(const std::string &bundleName, int32_t flag, int32_t appIndex,
        NotificationBundleManagerInfo &bundleInfo, int32_t userId) = 0;

    // virtual bool CheckBundleImplExtensionAbility(const sptr<NotificationBundleOption> &bundleOption) = 0;

    virtual bool CheckCurrentUserIdApp(const std::string &bundleName, const int32_t uid, const int32_t userId) = 0;

    /**
     * @brief Check API compatibility.
     *
     * @param bundleOption Indicates the bundle option.
     * @return Returns the check result.
     */
    virtual bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption) = 0;

    /**
     * @brief Check API compatibility.
     *
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the bundle uid.
     * @return Returns the check result.
     */
    virtual bool CheckApiCompatibility(const std::string &bundleName, const int32_t &uid) = 0;

    virtual bool IsAncoApp(const std::string &bundleName, int32_t uid) = 0;

    virtual bool IsAtomicServiceByBundle(const std::string &bundleName, const int32_t userId) = 0;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    /**
     * @brief Check whether the specified bundle has the distributed notification supported.
     *
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the check result.
     */
    virtual bool GetDistributedNotificationEnabled(const std::string &bundleName, const int32_t userId) = 0;
#endif

};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
