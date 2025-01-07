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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SUBSCRIBER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SUBSCRIBER_H

#include "notification_subscriber.h"

#include "device_manager.h"
#include "distributed_device_data.h"

namespace OHOS {
namespace Notification {
class DistribuedSubscriber : public NotificationSubscriber {
public:
    ~DistribuedSubscriber() override;
    void OnDied() override;
    void OnConnected() override;
    void OnDisconnected() override;
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override;
    void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override;
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;
    void OnApplicationInfoNeedChanged(const std::string& bundleName) override;
    void SetLocalDevice(DistributedDeviceInfo localDevice);
    void SetPeerDevice(DistributedDeviceInfo localDevice);
    bool CheckNeedCollaboration(const std::shared_ptr<Notification> &notification);
    bool CheckCollaborativeRemoveType(const NotificationConstant::SlotType& slotType);

private:
    DistributedDeviceInfo localDevice_;
    DistributedDeviceInfo peerDevice_;
};
}
}

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SUBSCRIBER_H
