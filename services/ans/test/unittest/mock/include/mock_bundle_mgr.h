/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_MOCK_BUNDLE_MANAGER_H
#define BASE_NOTIFICATION_MOCK_BUNDLE_MANAGER_H

#include "bundle_info.h"
#include "iremote_proxy.h"
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit BundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl) {}
    virtual ~BundleMgrProxy() {}

    ErrCode GetNameForUid(const int uid, std::string &name) override;
    bool GetBundleInfo(const std::string &bundleName, const BundleFlag flag,
        BundleInfo &bundleInfo, int32_t userId) override;
    int GetUidByBundleName(const std::string &bundleName, const int userId) override;
    bool GetApplicationInfo(
        const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo) override;
};
}  // namespace AppExecFwk

namespace Notification {

void MockIsNonBundleName(bool isNonBundleName);

void MockDistributedNotificationEnabled(bool isEnable);
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_OHOS_EDM_MOCK_BUNDLE_MANAGER_H
