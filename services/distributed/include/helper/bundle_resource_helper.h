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

private:
    void Connect();
    void Disconnect();
    void OnRemoteDied(const wptr<IRemoteObject> &object);

    sptr<AppExecFwk::IBundleMgr> bundleMgr_ = nullptr;
    std::mutex connectionMutex_;
    sptr<BundleDeathRecipient> deathRecipient_ = nullptr;

    DECLARE_DELAYED_SINGLETON(BundleResourceHelper)
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_RESOURCE_HELPER_H
