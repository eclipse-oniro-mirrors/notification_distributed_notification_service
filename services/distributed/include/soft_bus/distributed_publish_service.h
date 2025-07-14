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

#ifndef DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_PUBLISH_SERVICE_H
#define DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_PUBLISH_SERVICE_H

#include "tlv_box.h"
#include "notification.h"
#include "request_box.h"
#include "notification_request.h"
#include "distributed_device_data.h"
#ifdef DISTRIBUTED_FEATURE_MASTER
#include "remove_box.h"
#include "batch_remove_box.h"
#else
#endif


namespace OHOS {
namespace Notification {
class DistributedPublishService {
public:
    static DistributedPublishService& GetInstance();
    void RemoveNotification(const std::shared_ptr<TlvBox>& boxMessage);
    void RemoveNotifications(const std::shared_ptr<TlvBox>& boxMessage);
    void BatchRemoveReport(const std::string &slotTypesString, const std::string &deviceId, const int result);
    int RemoveDistributedNotifications(const std::vector<std::string>& hashcodes);
    void OnRemoveNotification(const DistributedDeviceInfo& peerDevice,
        std::string hashCode, int32_t slotTypes);
    void OnRemoveNotifications(const DistributedDeviceInfo& peerDevice,
        std::string hashCodes, std::string slotTypes);

#ifdef DISTRIBUTED_FEATURE_MASTER
    void RemoveAllDistributedNotifications(DistributedDeviceInfo& deviceInfo);
    void SyncLiveViewNotification(const DistributedDeviceInfo peerDevice, bool isForce);
    void SyncLiveViewList(const DistributedDeviceInfo device, const std::vector<sptr<Notification>>& notifications);
    void SyncLiveViewContent(const DistributedDeviceInfo device, const std::vector<sptr<Notification>>& notifications);
    void SendNotifictionRequest(const std::shared_ptr<Notification> request,
        const DistributedDeviceInfo& peerDevice, bool isSyncNotification = false);
    bool SetNotificationExtendInfo(const sptr<NotificationRequest> notificationRequest,
            int32_t deviceType, bool isSyncNotification, std::shared_ptr<NotificationRequestBox>& requestBox);
private:
    void SyncNotifictionList(const DistributedDeviceInfo& peerDevice,
        const std::vector<std::string>& notificationList);
    void SetNotificationButtons(const sptr<NotificationRequest> notificationRequest, int32_t deviceType,
        NotificationConstant::SlotType slotType, std::shared_ptr<NotificationRequestBox>& requestBox);
    void SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
        NotificationContent::Type type, std::shared_ptr<NotificationRequestBox>& requestBox);
    bool ForWardRemove(const std::shared_ptr<BoxBase>& boxMessage, std::string& deviceId);
    std::shared_ptr<NotificationRemoveBox> MakeRemvoeBox(std::string &hashCode, int32_t &slotTypes);
    std::shared_ptr<BatchRemoveNotificationBox> MakeBatchRemvoeBox(std::vector<std::string>& hashCodes,
        std::string &slotTypes);
    bool FillSyncRequestExtendInfo(const sptr<NotificationRequest> notificationRequest, int32_t deviceTypeId,
        std::shared_ptr<NotificationRequestBox>& requestBox, AAFwk::WantParams& wantParam);
    bool FillNotSyncRequestExtendInfo(const sptr<NotificationRequest> notificationRequest, int32_t deviceType,
        std::shared_ptr<NotificationRequestBox>& requestBox, AAFwk::WantParams& wantParam);
#else
    void PublishNotification(const std::shared_ptr<TlvBox>& boxMessage);
    void PublishSynchronousLiveView(const std::shared_ptr<TlvBox>& boxMessage);
    void RemoveAllDistributedNotifications(const std::shared_ptr<TlvBox>& boxMessage);
private:
    void MakeExtendInfo(const NotificationRequestBox& box, sptr<NotificationRequest>& request);
    void MakeNotificationButtons(const NotificationRequestBox& box,
        NotificationConstant::SlotType slotType, sptr<NotificationRequest>& request);
    void MakePadNotificationButtons(const NotificationRequestBox& box, sptr<NotificationRequest>& request);
    void MakeNotificationContent(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView, int32_t contentType);
    void MakeNotificationIcon(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        bool isCommonLiveView);
    void MakeNotificationReminderFlag(const NotificationRequestBox& box,
        sptr<NotificationRequest>& request);
    void MakeNotificationBasicContent(const NotificationRequestBox& box, sptr<NotificationRequest>& request,
        int32_t contentType);
#endif
};
}
}
#endif
