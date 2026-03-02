/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_BUNDLE_SERVICE_H
#define DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_BUNDLE_SERVICE_H

#include <set>
#include <map>

#include "tlv_box.h"
#include "application_change_box.h"
#include "distributed_device_data.h"
#include "notification_application_change_info.h"

namespace OHOS {
namespace Notification {
class DistributedBundleService {
public:
    static DistributedBundleService& GetInstance();

    void HandleLocalApplicationChanged(const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo);
    void HandleRemoteApplicationChanged(const std::shared_ptr<TlvBox>& boxMessage);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void SetDeviceBundleList(const std::shared_ptr<TlvBox>& boxMessage);
    bool GetApplicationResource(NotificationDistributedBundle& info);
    void SendDistributedBundleInfo(const DistributedDeviceInfo device);
    void HandleApplicationEnableChange(const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo,
        NotificationDistributedBundle distributedBundle, DistributedBundleChangeType changeType);
#else
    void SyncInstalledBundles(const DistributedDeviceInfo& peerDevice, bool isForce);
    void SendInstalledBundles(const DistributedDeviceInfo& peerDevice, const std::string& localDeviceId,
        const std::vector<std::pair<std::string, std::string>>& bundles, int32_t type);
#endif
private:
    void SendDistributedBundleChange(const std::vector<NotificationDistributedBundle>& applicationList,
        DistributedBundleChangeType type);
};
}
}
#endif // DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_BUNDLE_SERVICE_H
