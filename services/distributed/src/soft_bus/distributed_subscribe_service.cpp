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
#include "distributed_observer_service.h"
#include "notification_subscribe_info.h"
#include "distributed_timer_service.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "distributed_preferences.h"
#include "batch_remove_box.h"
#include "remove_box.h"
namespace OHOS {
namespace Notification {

const std::string DISTRIBUTED_LABEL = "ans_distributed";

std::string SubscribeTransDeviceType(uint16_t deviceType_)
{
    switch (deviceType_) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "wearable";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return "Pad";
        }
        default:
            return "";
    }
}

void DistributedService::SubscribeNotifictaion(const DistributedDeviceInfo peerDevice)
{
    if (peerDevice_.find(peerDevice.deviceId_) == peerDevice_.end()) {
        ANS_LOGI("Local device no %{public}s %{public}d.", peerDevice.deviceId_.c_str(),
            peerDevice.deviceType_);
        return;
    }

    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    subscriber->SetLocalDevice(localDevice_);
    subscriber->SetPeerDevice(peerDevice);
    sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddDeviceType(SubscribeTransDeviceType(peerDevice.deviceType_));
    subscribeInfo->AddAppUserId(userId_);
    subscribeInfo->SetNeedNotifyApplication(true);
    int result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        subscriberMap_.insert(std::make_pair(peerDevice.deviceId_, subscriber));
        peerDevice_[peerDevice.deviceId_].peerState_ = DeviceState::STATE_ONLINE;
        DistributedTimerService::GetInstance().CancelTimer(peerDevice.deviceId_);
        if (callBack_ == nullptr) {
            ANS_LOGW("Dans status callback is null.");
        } else {
            callBack_(peerDevice.deviceId_, DeviceState::STATE_ONLINE, false);
        }
    }
    ANS_LOGI("Subscribe notification %{public}s %{public}d %{public}d %{public}d.",
        peerDevice.deviceId_.c_str(), peerDevice.deviceType_, userId_, result);
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

        if (NotificationHelper::UnSubscribeNotification(iter->second) == 0) {
            subscriberMap_.erase(deviceId);
            peerDevice_.erase(deviceId);
            if (callBack_ == nullptr) {
                ANS_LOGW("Dans status callback is null.");
            } else {
                callBack_(deviceId, DeviceState::STATE_OFFLINE, false);
            }
        }
        if (peerDevice_.empty()) {
            DistributedTimerService::GetInstance().StartTimer(localDevice_.deviceId_,
                GetCurrentTime() + THIRTY_SECEND);
        }
        ANS_LOGI("UnSubscribe notification %{public}s %{public}d.", deviceId.c_str(), deviceType);
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
        requestBox.SetContentType(static_cast<int32_t>(requestPoint->GetNotificationType()));
        requestBox.SetReminderFlag(requestPoint->GetFlags()->GetReminderFlags());
        requestBox.SetCreatorBundleName(request->GetBundleName());
        if (requestPoint->GetBigIcon() != nullptr) {
            requestBox.SetBigIcon(requestPoint->GetBigIcon());
        }
        if (requestPoint->GetOverlayIcon() != nullptr) {
            requestBox.SetOverlayIcon(requestPoint->GetOverlayIcon());
        }
        bool isCommonLiveView = requestPoint->IsCommonLiveView();
        if (isCommonLiveView) {
            std::vector<uint8_t> buffer;
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewEncodeContent(requestPoint, buffer);
            requestBox.SetCommonLiveView(buffer);
        } else {
            auto content = request->GetNotificationRequestPoint()->GetContent();
            requestBox.SetNotificationTitle(content->GetNotificationContent()->GetTitle());
            requestBox.SetNotificationText(content->GetNotificationContent()->GetText());
        }
        if (!requestBox.Serialize()) {
            ANS_LOGW("Dans OnConsumed serialize failed.");
            return;
        }
        DistributedPreferences::GetInstance()->AddCollaborativeNotification(request->GetKey());
        DistributedClient::GetInstance().SendMessage(requestBox.GetByteBuffer(), requestBox.GetByteLength(),
            TransDataType::DATA_TYPE_BYTES, peerDevice.deviceId_, peerDevice.deviceType_);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([peerDevice, notifications, this]() {
        BatchRemoveNotifticationBox batchRemoveBox;
        std::vector<std::string> notificationKeys;
        for (auto notification : notifications) {
            if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
                continue;
            }
            if (!notification->GetNotificationRequestPoint()->GetDistributedCollaborate() &&
                !DistributedPreferences::GetInstance()->CheckCollaborativeNotification(notification->GetKey())) {
                continue;
            }
            ANS_LOGI("dans OnBatchCanceled %{public}s", notification->Dump().c_str());
            notificationKeys.push_back(GetNotificationKey(notification));
        }
        if (!notificationKeys.empty()) {
            batchRemoveBox.SetNotificationHashCode(notificationKeys[0]);
        }
        batchRemoveBox.SetNotificationKeys(notificationKeys);

        if (!batchRemoveBox.Serialize()) {
            ANS_LOGW("dans OnCanceled serialize failed");
            return;
        }
        DistributedClient::GetInstance().SendMessage(batchRemoveBox.GetByteBuffer(), batchRemoveBox.GetByteLength(),
            TransDataType::DATA_TYPE_MESSAGE, peerDevice.deviceId_, peerDevice.deviceType_);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnCanceled(const std::shared_ptr<Notification>& notification,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null");
        return;
    }
    std::function<void()> task = std::bind([peerDevice, notification, this]() {
        NotificationRemoveBox removeBox;
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            return;
        }
        if (!notification->GetNotificationRequestPoint()->GetDistributedCollaborate() &&
            !DistributedPreferences::GetInstance()->CheckCollaborativeNotification(notification->GetKey())) {
            ANS_LOGE("notification not collaborative");
            return;
        }
        ANS_LOGI("dans OnCanceled %{public}s", notification->Dump().c_str());
        removeBox.SetNotificationHashCode(GetNotificationKey(notification));
        if (!removeBox.Serialize()) {
            ANS_LOGW("dans OnCanceled serialize failed");
            return;
        }
        DistributedClient::GetInstance().SendMessage(removeBox.GetByteBuffer(), removeBox.GetByteLength(),
            TransDataType::DATA_TYPE_MESSAGE, peerDevice.deviceId_, peerDevice.deviceType_);
    });
    serviceQueue_->submit(task);
}

std::string DistributedService::GetNotificationKey(const std::shared_ptr<Notification>& notification)
{
    std::string notificationKey = notification->GetKey();
    if (notification->GetNotificationRequestPoint()->GetDistributedCollaborate()) {
        size_t pos = notificationKey.find(DISTRIBUTED_LABEL);
        if (pos != std::string::npos) {
            notificationKey.erase(pos, DISTRIBUTED_LABEL.length());
        }
    } else {
        notificationKey = DISTRIBUTED_LABEL + notificationKey;
    }
    return notificationKey;
}
}
}
