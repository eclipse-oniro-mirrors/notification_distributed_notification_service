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

namespace OHOS {
namespace Notification {

class DistributedService {
public:
    DistributedService();
    static DistributedService& GetInstance();
    void SubscribeNotifictaion(const DistributedDeviceInfo peerDevice);
    void UnSubscribeNotifictaion(const std::string &deviceId, uint16_t deviceType);
    void initService(const std::string &deviceId, uint16_t deviceType);
    void OnReceiveMsg(const void *data, uint32_t dataLen);
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const DistributedDeviceInfo& peerDevice);
    void InitDeviceState(const DistributedDeviceInfo peerDevice);
    void SyncDeviceState(int32_t state);
private:
    void PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage);
    void SetDeviceState(const std::shared_ptr<TlvBox>& boxMessage);
    void MakeNotifictaionContent(const NotifticationRequestBox& box, NotificationRequest& request);
    void MakeNotifictaionIcon(const NotifticationRequestBox& box, NotificationRequest& request);
    void MakeNotifictaionReminderFlag(const NotifticationRequestBox& box, NotificationRequest& request);
    DistributedDeviceInfo localDevice_;
    std::map<std::string, DistributedDeviceInfo> peerDevice_;
    std::shared_ptr<ffrt::queue> serviceQueue_ = nullptr;
    std::map<std::string, std::shared_ptr<DistribuedSubscriber>> subscriberMap_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_H
