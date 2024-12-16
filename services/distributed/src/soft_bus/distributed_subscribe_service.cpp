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
#include "distributed_service.h"

#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distribued_screenlock_service.h"

namespace OHOS {
namespace Notification {

void DistributedService::SubscribeNotifictaion(const DistributedDeviceInfo peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> subscribeTask = std::bind([&, peerDevice]() {
        std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
        subscriber->SetLocalDevice(localDevice_);
        subscriber->SetPeerDevice(peerDevice);
        int result = NotificationHelper::SubscribeNotification(subscriber);
        if (result == 0) {
            subscriberMap_.insert(std::make_pair(peerDevice.deviceId_, subscriber));
            peerDevice_.insert(std::make_pair(peerDevice.deviceId_, peerDevice));
        }
        ANS_LOGI("Subscribe notification %{public}s %{public}d %{public}d.",
            peerDevice.deviceId_.c_str(), peerDevice.deviceType_, result);
    });
    serviceQueue_->submit(subscribeTask);
}

void DistributedService::UnSubscribeNotifictaion(const std::string &deviceId, uint16_t deviceType)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> subscribeTask = std::bind([&, deviceId, deviceType]() {
        auto iter = subscriberMap_.find(deviceId);
        if (iter == subscriberMap_.end()) {
            ANS_LOGI("UnSubscribe invalid %{public}s %{public}d.", deviceId.c_str(), deviceType);
            return;
        }
        // Refresh device status, Todo
        int result = NotificationHelper::UnSubscribeNotification(iter->second);
        if (result == 0) {
            subscriberMap_.erase(deviceId);
            peerDevice_.erase(deviceId);
        }
        ANS_LOGI("UnSubscribe notification %{public}s %{public}d %{public}d.", deviceId.c_str(), deviceType, result);
    });
    serviceQueue_->submit(subscribeTask);
}

void DistributedService::OnConsumed(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([peerDevice, request]() {
        NotifticationRequestBox requestBox;
        ANS_LOGI("Dans OnConsumed %{public}s", request->Dump().c_str());
        if (request == nullptr || request->GetNotificationRequestPoint() == nullptr) {
            return;
        }
        auto requestPoint = request->GetNotificationRequestPoint();
        requestBox.SetNotificationHashCode(request->GetKey());
        requestBox.SetSlotType(static_cast<int32_t>(requestPoint->GetSlotType()));
        requestBox.SetReminderFlag(requestPoint->GetFlags()->GetReminderFlags());
        requestBox.SetCreatorBundleName(request->GetBundleName());
        if (requestPoint->GetBigIcon() != nullptr) {
            requestBox.SetBigIcon(requestPoint->GetBigIcon());
        }
        if (requestPoint->GetOverlayIcon() != nullptr) {
            requestBox.SetOverlayIcon(requestPoint->GetOverlayIcon());
        }
        auto content = request->GetNotificationRequestPoint()->GetContent();
        requestBox.SetNotificationTitle(content->GetNotificationContent()->GetTitle());
        requestBox.SetNotificationText(content->GetNotificationContent()->GetText());
        if (!requestBox.Serialize()) {
            ANS_LOGW("Dans OnConsumed serialize failed.");
            return;
        }
        DistributedClient::GetInstance().SendMessage(requestBox.GetByteBuffer(), requestBox.GetByteLength(),
            TransDataType::DATA_TYPE_BYTES, peerDevice.deviceId_, peerDevice.deviceType_);
    });
    serviceQueue_->submit(task);
}

}
}
