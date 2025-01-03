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
namespace OHOS {
namespace Notification {

class DistributedService {
public:
    DistributedService();
    static DistributedService& GetInstance();
    void SubscribeNotifictaion(const DistributedDeviceInfo device);
    void UnSubscribeNotifictaion(const std::string &deviceId, uint16_t deviceType);
    int32_t InitService(const std::string &deviceId, uint16_t deviceType,
        std::function<bool(std::string, int32_t, bool)> callback);
    void OnReceiveMsg(const void *data, uint32_t dataLen);
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const DistributedDeviceInfo& device);
    void OnCanceled(const std::shared_ptr<Notification>& notification, const DistributedDeviceInfo& peerDevice);
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
        const DistributedDeviceInfo& peerDevice);
    void InitDeviceState(const DistributedDeviceInfo device);
    void SyncDeviceState(int32_t state);
    void SetCurrentUserId(int32_t userId);
    void SyncConnectedDevice(DistributedDeviceInfo device);
    int32_t SyncDeviceMatch(const DistributedDeviceInfo device, MatchType type);
    void AddDevice(DistributedDeviceInfo device);
    void HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage);
    void DestoryService();
    void ReportDeviceStatus(std::string deviceId);
    void ReportBundleIconList(const DistributedDeviceInfo peerDevice);
    void UpdateBundlesIcon(const std::unordered_map<std::string, std::string>& icons,
        const DistributedDeviceInfo peerDevice);
    void RequestBundlesIcon(const DistributedDeviceInfo peerDevice);
    void HandleBundlesEvent(const std::string& bundleName, const std::string& action);
    void HandleBundleChanged(const std::string& bundleName, bool updatedExit);
    std::string GetNotificationKey(const std::shared_ptr<Notification>& notification);
private:
    int64_t GetCurrentTime();
    void HandleBundleRemoved(const std::string& bundleName);
    bool GetBundleResourceInfo(const std::string bundleName, std::string& icon);
    void HandleBundleIconSync(const std::shared_ptr<TlvBox>& boxMessage);
    void GenerateBundleIconSync(const DistributedDeviceInfo& device);
    bool CheckPeerDevice(const BundleIconBox& boxMessage, DistributedDeviceInfo& device);
    void PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage);
    void HandleDeviceState(const std::shared_ptr<TlvBox>& boxMessage);
    void MakeNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView, int32_t contentType);
    void MakeNotifictaionIcon(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView);
    void SetNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
        int32_t contentType);
    void MakeNotifictaionReminderFlag(const NotifticationRequestBox& box, sptr<NotificationRequest>& request);
    void RemoveNotifictaion(const std::shared_ptr<TlvBox>& boxMessage);
    void RemoveNotifictaions(const std::shared_ptr<TlvBox>& boxMessage);
    void SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
        NotificationContent::Type type, NotifticationRequestBox &requestBox);
    std::function<bool(std::string, int32_t, bool)> callBack_ = nullptr;
    std::set<std::string> bundleIconCache_;
    int32_t userId_ = DEFAULT_USER_ID;
    DistributedDeviceInfo localDevice_;
    std::map<std::string, DistributedDeviceInfo> peerDevice_;
    std::shared_ptr<ffrt::queue> serviceQueue_ = nullptr;
    std::map<std::string, std::shared_ptr<DistribuedSubscriber>> subscriberMap_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H