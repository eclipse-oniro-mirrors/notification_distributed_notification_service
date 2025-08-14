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

#ifndef NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_DEVICE_DATA_SERVICE_H
#define NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_DEVICE_DATA_SERVICE_H

#include <set>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "ffrt.h"

namespace OHOS {
namespace Notification {

struct DeviceData {
    std::string deviceId;
    std::string deviceType;
    bool notificationSyncEnable = true;
    bool liveViewSyncEnable = true;
    std::unordered_map<std::string, std::string> installedBundles;
};

class DistributedDeviceDataService {
public:
    static DistributedDeviceDataService& GetInstance();

    void ResetTargetDevice(const std::string& deviceType, const std::string& deviceId);
    int32_t SetDeviceSyncSwitch(const std::string& deviceType, const std::string& deviceId,
        bool notificationEnable, bool liveViewEnable);
    int32_t SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList);
    int32_t GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        std::vector<std::string>& bundleList, std::vector<std::string>& labelList);
    bool CheckDeviceBundleExist(const std::string& deviceType, const std::string& deviceId,
        const std::string& bundleName, const std::string& label);
    bool GetDeviceNotificationEnable(const std::string& deviceType, const std::string& deviceId);
    bool GetDeviceLiveViewEnable(const std::string& deviceType, const std::string& deviceId);

private:
    DistributedDeviceDataService() = default;
    ~DistributedDeviceDataService() = default;

    ffrt::mutex lock_;
    std::vector<DeviceData> devicesData_;
};
}
}
#endif // NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_DEVICE_DATA_SERVICE_H
