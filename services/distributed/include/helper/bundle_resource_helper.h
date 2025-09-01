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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_RESOURCE_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_RESOURCE_HELPER_H

#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "refbase.h"
#include "singleton.h"
#include "ans_log_wrapper.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {


class BundleDeathRecipient : public IRemoteObject::DeathRecipient {
public:

    explicit BundleDeathRecipient(std::function<void(const wptr<IRemoteObject> &)> callback)
    {
        callback_ = callback;
    }

    ~BundleDeathRecipient()
    {
        callback_ = nullptr;
    }

    void OnRemoteDied(const wptr<IRemoteObject> &object)
    {
        if (callback_ != nullptr) {
            callback_(object);
        }
    }

private:
    std::function<void(const wptr<IRemoteObject> &)> callback_;
};

class BundleResourceHelper : public DelayedSingleton<BundleResourceHelper> {
public:
    /**
     * @brief Obtains bundle info by bundle name.
     *
     * @param bundleName Indicates the bundle name.
     * @param flag Indicates the bundle flag.
     * @param bundleInfo Indicates the bundle resource.
     * @param appIndex Indicates the appindex.
     * @return Returns the check result.
     */
    ErrCode GetBundleInfo(const std::string &bundleName,
        AppExecFwk::BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0);

    /**
     * @brief Obtains all installed bundle info.
     *
     * @param flag Indicates the bundle flag.
     * @param bundleInfo Indicates the bundle resource.
     * @param userId Indicates the userId.
     * @return Returns the invock result.
     */
    ErrCode GetAllBundleInfos(int32_t flags, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId);

    /**
     * @brief Obtains all installed bundle info.
     *
     * @param bundlesName Indicates the bundle name.
     * @param userId Indicates the userId.
     * @return Returns the invock result.
     */
    ErrCode GetAllInstalledBundles(std::vector<std::pair<std::string, std::string>>& bundlesName, int32_t userId);

    ErrCode GetApplicationInfo(const std::string &appName, int32_t flags, int32_t userId,
        AppExecFwk::ApplicationInfo &appInfo);

    bool CheckSystemApp(const std::string& bundleName, int32_t userId);

    ErrCode GetBundleInfoV9(const std::string& bundleName, int32_t userId,
        AppExecFwk::BundleInfo& bundleInfo);

    int32_t GetAppIndexByUid(const int32_t uid);
private:
    void Connect();
    void Disconnect();
    void OnRemoteDied(const wptr<IRemoteObject> &object);

    sptr<AppExecFwk::IBundleMgr> bundleMgr_ = nullptr;
    ffrt::mutex connectionMutex_;
    sptr<BundleDeathRecipient> deathRecipient_ = nullptr;

    DECLARE_DELAYED_SINGLETON(BundleResourceHelper)
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_RESOURCE_HELPER_H
