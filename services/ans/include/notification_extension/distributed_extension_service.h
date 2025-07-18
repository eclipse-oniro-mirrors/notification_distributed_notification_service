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
#include "notification_config_parse.h"
#include "distributed_data_define.h"
#include "ffrt.h"

#include <set>
#include <mutex>
#include <unordered_set>

namespace OHOS {
namespace Notification {
using namespace DistributedHardware;

class DistributedDeviceInfo {
public:
    DistributedDeviceInfo() {}
    DistributedDeviceInfo(std::string deviceId, std::string deviceName,
        std::string networkId, uint16_t deviceType) : deviceId_(deviceId),
        deviceName_(deviceName), networkId_(networkId), deviceType_(deviceType) { }
    ~DistributedDeviceInfo() = default;
    std::string deviceId_;
    std::string deviceName_;
    std::string networkId_;
    uint16_t deviceType_;
};

class DistributedExtensionService {
public:
    bool initConfig();
    int32_t InitDans();
    int32_t ReleaseLocalDevice();
    void OnAllConnectOnline();
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo);
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo);
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo);
    void DeviceStatusChange(const DeviceStatueChangeInfo& changeInfo);
    static DistributedExtensionService& GetInstance();
    static std::string TransDeviceTypeToName(uint16_t deviceType_);
    static std::string DeviceTypeToTypeString(uint16_t deviceType_);
    void HADotCallback(int32_t code, int32_t ErrCode, uint32_t branchId, std::string reason);
    void SendReportCallback(int32_t messageType, int32_t errCode, std::string reason);
    int32_t GetOperationReplyTimeout();
    int32_t TransDeviceIdToUdid(const std::string& networkId, std::string& udid);
    void HaOperationCallback(const std::string& deviceType, int32_t sceneType, int32_t slotType, std::string reason);

private:
    DistributedExtensionService();
    ~DistributedExtensionService();
    void SetMaxContentLength(nlohmann::json &configJson);
    void SetOperationReplyTimeout(nlohmann::json &configJson);
    bool SetLocalType(nlohmann::json &configJson);
    bool SetSupportPeerDevice(nlohmann::json &configJson);
    bool SetMaxTitleLength(nlohmann::json &configJson);

    ffrt::mutex mapLock_;
    std::atomic<bool> dansRunning_ = false;
    std::shared_ptr<ffrt::queue> distributedQueue_ = nullptr;
    std::shared_ptr<NotificationLoadUtils> dansHandler_;
    std::map<std::string, DistributedDeviceInfo> deviceMap_;
    DistributedDeviceConfig deviceConfig_;
};
}
}
#endif // NOTIFICATION_DISTRIBUTED_EXTENSION_SERVICE_H
