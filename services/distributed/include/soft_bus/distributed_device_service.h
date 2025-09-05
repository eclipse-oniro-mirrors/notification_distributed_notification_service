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

#ifndef DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_DEVICE_SERVICE_H
#define DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_DEVICE_SERVICE_H

#include "distributed_device_data.h"

#include <thread>
#include "match_box.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
class DistributedDeviceService {
public:
    static constexpr int32_t STATE_TYPE_BOTH = 3;
    static constexpr int32_t STATE_TYPE_SWITCH = 2;
    static constexpr int32_t STATE_TYPE_LOCKSCREEN = 1;
    static constexpr int32_t SYNC_BUNDLE_ICONS = 1;
    static constexpr int32_t SYNC_LIVE_VIEW = 2;
    static constexpr int32_t SYNC_INSTALLED_BUNDLE = 3;
    static constexpr int32_t DEVICE_USAGE = 4;

    static DistributedDeviceService& GetInstance();
    static std::string DeviceTypeToTypeString(uint16_t deviceType);

    bool IsLocalPadOrPC();
    bool IsReportDataByHa();
    void InitLocalDevice(const std::string &deviceId, uint16_t deviceType);
    DistributedDeviceInfo GetLocalDevice();
    void SetSubscribeAllConnect(bool subscribe);
    bool IsSubscribeAllConnect();
    bool CheckNeedSubscribeAllConnect();
    bool IsSyncLiveView(const std::string& deviceId, bool forceSync);
    bool IsSyncIcons(const std::string& deviceId, bool forceSync);
    bool IsSyncInstalledBundle(const std::string& deviceId, bool forceSync);
    bool GetDeviceInfoByUdid(const std::string& udid, DistributedDeviceInfo& device);
    bool GetDeviceInfo(const std::string& deviceId, DistributedDeviceInfo& device);
    void SetDeviceState(const std::string& deviceId, int32_t state);
    void SetDeviceSyncData(const std::string& deviceId, int32_t type, bool syncData);
    bool CheckDeviceExist(const std::string& deviceId);
    bool CheckDeviceNeedSync(const std::string& deviceId);
    void IncreaseDeviceSyncCount(const std::string& deviceId);
    void AddDeviceInfo(DistributedDeviceInfo deviceItem);
    void ResetDeviceInfo(const std::string& deviceId, int32_t peerState);
    void DeleteDeviceInfo(const std::string& deviceId);
    std::map<std::string, DistributedDeviceInfo>& GetDeviceList();
    void GetDeviceList(std::map<std::string, DistributedDeviceInfo>& peerDevices);
    void SyncDeviceMatch(const DistributedDeviceInfo peerDevice, MatchType type);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void SetDeviceStatus(const std::shared_ptr<TlvBox>& boxMessage);
#else
    void InitCurrentDeviceStatus();
    bool GetDeviceInfoByNetworkId(const std::string& id, DistributedDeviceInfo& device);
    void SyncDeviceStatus(int32_t type, int32_t status, bool notificationEnable, bool liveViewEnable);
#endif

private:
    ffrt::mutex mapLock_;
    bool subscribeAllConnect = false;
    DistributedDeviceInfo localDevice_;
    std::map<std::string, DistributedDeviceInfo> peerDevice_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_DEVICE_SERVICE_H
