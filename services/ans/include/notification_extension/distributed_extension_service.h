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

#ifndef NOTIFICATION_DISTRIBUTED_EXTENSION_SERVICE_H
#define NOTIFICATION_DISTRIBUTED_EXTENSION_SERVICE_H

#include "device_manager.h"

#include "notifictaion_load_utils.h"
#include "ffrt.h"
#include <set>

namespace OHOS {
namespace Notification {
using namespace DistributedHardware;
class DistributedDeviceInfo {
public:
    DistributedDeviceInfo(std::string deviceId, std::string deviceName,
        std::string networkId, uint16_t deviceType) : deviceId_(deviceId),
        deviceName_(deviceName), networkId_(networkId), deviceType_(deviceType) { }
    ~DistributedDeviceInfo() = default;
    std::string deviceId_;
    std::string deviceName_;
    std::string networkId_;
    uint16_t deviceType_;
};

class DistributedDeviceConfig {
public:
    std::string localType;
    std::set<std::string> supportPeerDevice_;
};

class DistributedExtensionService {
public:
    bool initConfig();
    int32_t InitDans();
    void CloseDans();
    int32_t ReleaseLocalDevice();
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo);
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo);
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo);
    static DistributedExtensionService& GetInstance();
private:
    DistributedExtensionService();
    ~DistributedExtensionService() = default;
    bool releaseSameDevice(const DmDeviceInfo &deviceInfo);
    std::atomic<bool> idle_ = false;
    std::atomic<bool> dansRunning_ = false;
    std::shared_ptr<ffrt::queue> distributedQueue_ = nullptr;
    std::shared_ptr<NotificationLoadUtils> dansHandler_;
    std::map<std::string, DistributedDeviceInfo> deviceMap_;
    DistributedDeviceConfig deviceConfig_;
};
}
}
#endif // NOTIFICATION_DISTRIBUTED_EXTENSION_SERVICE_H
