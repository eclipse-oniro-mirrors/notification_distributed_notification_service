/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_BUNDLE_MANAGER_HELPER_H
#define NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_BUNDLE_MANAGER_HELPER_H

#include <memory>
#include <mutex>
#include <string>

#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "refbase.h"
#include "remote_death_recipient.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
class ReminderBundleManagerHelper : public DelayedSingleton<ReminderBundleManagerHelper> {
public:
    /**
     * @brief Obtains the bundle name base on the specified uid.
     *
     * @param uid Indicates the specified uid.
     * @return Returns the bundle name.
     */
    std::string GetBundleNameByUid(int32_t uid);

    /**
     * @brief Obtains the default uid.
     *
     * @param bundle Indicates the bundle name.
     * @param userId Indicates the user id.
     * @return Returns the uid.
     */
    int32_t GetDefaultUidByBundleName(const std::string &bundle, const int32_t userId);

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
     * @brief Obtains the app index by uid.
     * @param uid Indicates uid.
     * @return Returns the query result if succeed, retrun 0(main index) otherwise.
     */
    int32_t GetAppIndexByUid(const int32_t uid);

private:
    void Connect();
    void Disconnect();

    void OnRemoteDied(const wptr<IRemoteObject> &object);

private:
    sptr<AppExecFwk::IBundleMgr> bundleMgr_ = nullptr;
    std::mutex connectionMutex_;
    sptr<RemoteDeathRecipient> deathRecipient_ = nullptr;

    DECLARE_DELAYED_SINGLETON(ReminderBundleManagerHelper)
};
}  // namespace Notification
}  // namespace OHOS
#endif  // NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_BUNDLE_MANAGER_HELPER_H
