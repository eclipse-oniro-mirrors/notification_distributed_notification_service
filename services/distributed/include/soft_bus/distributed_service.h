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
    void SubscribeNotifictaion(const DistributedDeviceInfo device);
    void UnSubscribeNotifictaion(const std::string &deviceId, uint16_t deviceType);
    int32_t InitService(const std::string &deviceId, uint16_t deviceType);
    void OnReceiveMsg(const void *data, uint32_t dataLen);
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const DistributedDeviceInfo& device);
    void OnCanceled(const std::shared_ptr<Notification>& notification, const DistributedDeviceInfo& peerDevice);
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
        const DistributedDeviceInfo& peerDevice);
    void InitDeviceState(const DistributedDeviceInfo device);
    void SyncDeviceState(int32_t state);
    void SyncConnectedDevice(DistributedDeviceInfo device);
    int32_t SyncDeviceMatch(const DistributedDeviceInfo device, MatchType type);
    void AddDevice(DistributedDeviceInfo device);
    void HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage);
    void DestoryService();
    void ReportBundleIconList(const DistributedDeviceInfo peerDevice);
    int32_t UpdateBundlesIcon(const std::unordered_map<std::string, std::string>& icons,
        const DistributedDeviceInfo peerDevice);
    void RequestBundlesIcon(const DistributedDeviceInfo peerDevice, bool isForce);
    void HandleBundlesEvent(const std::string& bundleName, const std::string& action);
    void HandleBundleChanged(const std::string& bundleName, bool updatedExit);
    std::string GetNotificationKey(const std::shared_ptr<Notification>& notification);
    ErrCode OnResponse(const std::shared_ptr<NotificationOperationInfo>& operationInfo,
        const DistributedDeviceInfo& device);
    void SendNotifictionRequest(const std::shared_ptr<Notification> request,
        const DistributedDeviceInfo& peerDevice, bool isSyncNotification = false);
    void SyncAllLiveViewNotification(const DistributedDeviceInfo peerDevice, bool isForce);
    void SyncNotifictionList(const DistributedDeviceInfo& peerDevice, const std::vector<std::string>& list);
    void HandleNotificationSync(const std::shared_ptr<TlvBox>& boxMessage);
    bool IsReportHa();

private:
    void OnHandleMsg(std::shared_ptr<TlvBox>& box);
    int64_t GetCurrentTime();
    void HandleBundleRemoved(const std::string& bundleName);
    bool GetBundleResourceInfo(const std::string bundleName, std::string& icon);
    void HandleBundleIconSync(const std::shared_ptr<TlvBox>& boxMessage);
    void GenerateBundleIconSync(const DistributedDeviceInfo& device);
    bool CheckPeerDevice(const BundleIconBox& boxMessage, DistributedDeviceInfo& device);
    void PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage);
    void HandleDeviceState(const std::shared_ptr<TlvBox>& boxMessage);
    void HandleResponseSync(const std::shared_ptr<TlvBox>& boxMessage);
    void MakeNotificationContent(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView, int32_t contentType);
    void MakeNotificationIcon(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView);
    void SetNotifictaionContent(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        int32_t contentType);
    void MakeNotificationReminderFlag(const NotificationRequestBox& box, sptr<NotificationRequest>& request);
    void RemoveNotification(const std::shared_ptr<TlvBox>& boxMessage);
    void RemoveNotifications(const std::shared_ptr<TlvBox>& boxMessage);
    void SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
        NotificationContent::Type type, std::shared_ptr<NotificationRequestBox>& requestBox);
    void GetNeedUpdateDevice(bool updatedExit, const std::string& bundleName,
        std::vector<DistributedDeviceInfo>& updateDeviceList);
    void TriggerJumpApplication(const std::string& hashCode);
    ErrCode TriggerReplyApplication(const std::string& hashCode, const NotificationResponseBox& responseBox);
    void HandleOperationResponse(const std::string& hashCode, const NotificationResponseBox& responseBox);
    void ReplyOperationResponse(const std::string& hashCode, const NotificationResponseBox& responseBox,
        OperationType operationType, uint32_t result);
    void SetNotificationButtons(const sptr<NotificationRequest> notificationRequest,
        NotificationConstant::SlotType slotType, std::shared_ptr<NotificationRequestBox>& requestBox);
    void MakeNotificationButtons(const NotificationRequestBox& box, NotificationConstant::SlotType slotType,
        sptr<NotificationRequest>& request);
    int32_t GetCurrentActiveUserId();
    void TriggerReplyWantAgent(const sptr<NotificationRequest> request, std::string actionName,
        int32_t errorCode, std::string desc);
    ErrCode GetNotificationButtonWantPtr(const std::string& hashCode, const std::string& actionName,
        std::shared_ptr<AAFwk::Want>& wantPtr, sptr<NotificationRequest>& request, std::string& userInputKey);

private:
    std::function<void(int32_t, int32_t, uint32_t, std::string)> haCallback_ = nullptr;
    std::function<void(int32_t, int32_t, std::string)> sendReportCallback_ = nullptr;
    std::map<std::string, std::set<std::string>> bundleIconCache_;
    DistributedDeviceInfo localDevice_;
    std::map<std::string, DistributedDeviceInfo> peerDevice_;
    std::shared_ptr<ffrt::queue> serviceQueue_ = nullptr;
    std::map<std::string, std::shared_ptr<DistribuedSubscriber>> subscriberMap_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H
