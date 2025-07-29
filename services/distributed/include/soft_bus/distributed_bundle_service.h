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
#include "distributed_device_data.h"

namespace OHOS {
namespace Notification {
class DistributedBundleService {
public:
    static DistributedBundleService& GetInstance();

    void HandleBundleIconSync(const std::shared_ptr<TlvBox>& boxMessage);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void RequestBundlesIcon(const DistributedDeviceInfo peerDevice, bool isForce);
    void GenerateBundleIconSync(const DistributedDeviceInfo& device);
    void HandleBundleRemoved(const std::string& bundleName);
    void HandleBundleChanged(const std::string& bundleName, bool updatedExit);
    void SetDeviceBundleList(const std::shared_ptr<TlvBox>& boxMessage);
private:
    int32_t UpdateBundlesIcon(const std::unordered_map<std::string, std::string>& icons,
        const DistributedDeviceInfo peerDevice);
    bool GetBundleResourceInfo(const std::string bundleName, std::string& icon);
    void GetNeedUpdateDevice(bool updatedExit, const std::string& bundleName,
        std::vector<DistributedDeviceInfo>& updateDeviceList);
#else
    void ReportBundleIconList(const DistributedDeviceInfo peerDevice);
    void SyncInstalledBundles(const DistributedDeviceInfo& peerDevice, bool isForce);
    void SendInstalledBundles(const DistributedDeviceInfo& peerDevice, const std::string& localDeviceId,
        const std::vector<std::pair<std::string, std::string>>& bundles, int32_t type);
#endif

private:
    std::map<std::string, std::set<std::string>> bundleIconCache_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_BUNDLE_SERVICE_H
