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

#include <sstream>

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
#include "distributed_preference.h"
#include "batch_remove_box.h"
#include "remove_box.h"

namespace OHOS {
namespace Notification {

const std::string DISTRIBUTED_LABEL = "ans_distributed";
const int32_t DEFAULT_FILTER_TYPE = 1;

std::string SubscribeTransDeviceType(uint16_t deviceType)
{
    switch (deviceType) {
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
    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::LIVE_VIEW);
    slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    subscribeInfo->SetSlotTypes(slotTypes);
    subscribeInfo->SetFilterType(DEFAULT_FILTER_TYPE);
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

void DistributedService::SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
    NotificationContent::Type type, NotifticationRequestBox &requestBox)
{
    if (content == nullptr || content->GetNotificationContent() == nullptr) {
        return;
    }
    std::string title;
    std::string text;
    switch (type) {
        case NotificationContent::Type::PICTURE:
        case NotificationContent::Type::BASIC_TEXT:
        case NotificationContent::Type::LIVE_VIEW:
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
        case NotificationContent::Type::MULTILINE: {
            std::shared_ptr<NotificationBasicContent> contentBasic =
                std::static_pointer_cast<NotificationBasicContent>(content->GetNotificationContent());
            title = contentBasic->GetTitle();
            text = contentBasic->GetText();
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            std::shared_ptr<NotificationLongTextContent> contentLong =
                std::static_pointer_cast<NotificationLongTextContent>(content->GetNotificationContent());
            title = contentLong->GetTitle();
            text = contentLong->GetLongText();
            break;
        }
        default:
            break;
    }
    requestBox.SetNotificationTitle(title);
    requestBox.SetNotificationText(text);
}

void DistributedService::OnConsumed(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, peerDevice, request]() {
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
        }
        SetNotificationContent(request->GetNotificationRequestPoint()->GetContent(),
            requestPoint->GetNotificationType(), requestBox);
        if (!requestBox.Serialize()) {
            ANS_LOGW("Dans OnConsumed serialize failed.");
            return;
        }
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

    std::ostringstream keysStream;
    for (auto notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
            continue;
        }
        ANS_LOGI("dans OnBatchCanceled %{public}s", notification->Dump().c_str());
        keysStream << GetNotificationKey(notification) << ' ';
    }
    std::string notificationKeys = keysStream.str();

    std::function<void()> task = std::bind([peerDevice, notifications, notificationKeys]() {
        BatchRemoveNotificationBox batchRemoveBox;
        if (!notificationKeys.empty()) {
            batchRemoveBox.SetNotificationHashCode(notificationKeys);
        }

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
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return;
    }
    std::string notificationKey = GetNotificationKey(notification);
    std::function<void()> task = std::bind([peerDevice, notification, notificationKey]() {
        NotificationRemoveBox removeBox;
        ANS_LOGI("dans OnCanceled %{public}s", notification->Dump().c_str());
        removeBox.SetNotificationHashCode(notificationKey);
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
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return "";
    }
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
