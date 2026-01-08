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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H

#include <string>
#include "ffrt.h"
#include "socket.h"
#include "distributed_subscriber.h"
#include "distributed_device_data.h"
#include "request_box.h"
#include "match_box.h"
#include <functional>
#include "bundle_icon_box.h"
#include <unordered_set>
#include "distributed_data_define.h"
#include "response_box.h"

namespace OHOS {
namespace Notification {

class DistributedService {
public:
    DistributedService();
    static DistributedService& GetInstance();
    void DestroyService();
    int32_t InitService(const std::string &deviceId, uint16_t deviceType);
    void AddDevice(DistributedDeviceInfo device, const std::string &extraData);
    void ReleaseDevice(const std::string &deviceId, uint16_t deviceType);
    void DeviceStatusChange(const DeviceStatueChangeInfo& changeInfo);
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const DistributedDeviceInfo& device);
    void OnApplicationInfnChanged(const std::string& bundleName);
    int32_t OnOperationResponse(const std::shared_ptr<NotificationOperationInfo>& operationInfo,
        const DistributedDeviceInfo& device);
    void OnCanceled(const std::shared_ptr<Notification>& notification, const DistributedDeviceInfo& peerDevice);
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
        const DistributedDeviceInfo& peerDevice);
    void OnReceiveMsg(const void *data, uint32_t dataLen);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void HandleBundlesEvent(const std::string& bundleName, const std::string& action);
    void HandleDeviceUsingChange(const DeviceStatueChangeInfo& changeInfo);
#else
    void SyncDeviceStatus(int32_t status);
    void SyncInstalledBundle(const std::string& bundleName, bool isAdd);
#endif
    std::string GetNotificationKey(const std::shared_ptr<Notification>& notification);
    constexpr static const char* WEARABLE_DEVICE_TYPE = "wearable";
    constexpr static const char* LITEWEARABLE_DEVICE_TYPE = "liteWearable";
    constexpr static const char* PAD_DEVICE_TYPE = "tablet";
    constexpr static const char* PC_DEVICE_TYPE = "2in1";
    constexpr static const char* PHONE_DEVICE_TYPE = "phone";
private:
    void OnHandleMsg(std::shared_ptr<TlvBox>& box);
    void ConnectPeerDevice(DistributedDeviceInfo device);
    void HandleStatusChange(const DeviceStatueChangeInfo& changeInfo);
    void HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage);
    bool OnConsumedSetFlags(const std::shared_ptr<Notification> &request,
        const DistributedDeviceInfo& peerDevice);
    void HandleMatchByType(const int32_t matchType, const DistributedDeviceInfo& device);
    bool CheckCollaborationAbility(const DistributedDeviceInfo device, const std::string &extraData);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void HandleSwitchChange(const DeviceStatueChangeInfo &changeInfo);
#endif

private:
    std::shared_ptr<ffrt::queue> serviceQueue_ = nullptr;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H
