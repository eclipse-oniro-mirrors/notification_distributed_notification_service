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
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "distributed_preference.h"
#include "batch_remove_box.h"
#include "ans_inner_errors.h"
#include "remove_box.h"
#include "response_box.h"

namespace OHOS {
namespace Notification {

const std::string DISTRIBUTED_LABEL = "ans_distributed";
const int32_t DEFAULT_FILTER_TYPE = 1;
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t BRANCH3_ID = 3;

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
    subscribeInfo->SetNeedNotifyResponse(true);
    int result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        auto iter = subscriberMap_.find(peerDevice.deviceId_);
        if (iter != subscriberMap_.end()) {
            NotificationHelper::UnSubscribeNotification(iter->second);
        }
        subscriberMap_[peerDevice.deviceId_] = subscriber;
        peerDevice_[peerDevice.deviceId_].peerState_ = DeviceState::STATE_ONLINE;
        if (haCallback_ != nullptr) {
            std::string reason = "deviceType: " + std::to_string(localDevice_.deviceType_) +
                                 " ; deviceId: " + AnonymousProcessing(localDevice_.deviceId_);
            haCallback_(PUBLISH_ERROR_EVENT_CODE, 0, BRANCH3_ID, reason);
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
        auto deviceIter = peerDevice_.find(deviceId);
        if (deviceIter != peerDevice_.end()) {
            ANS_LOGI("UnSubscribe device %{public}s %{public}d.", deviceId.c_str(), deviceType);
            peerDevice_.erase(deviceId);
        }

        auto iter = subscriberMap_.find(deviceId);
        if (iter == subscriberMap_.end()) {
            ANS_LOGI("UnSubscribe invalid %{public}s %{public}d.", deviceId.c_str(), deviceType);
            return;
        }

        if (NotificationHelper::UnSubscribeNotification(iter->second) == 0) {
            subscriberMap_.erase(deviceId);
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
        if (request == nullptr || request->GetNotificationRequestPoint() == nullptr) {
            return;
        }
        auto requestPoint = request->GetNotificationRequestPoint();
        ANS_LOGI("Dans OnConsumed %{public}s", requestPoint->Dump().c_str());
        requestBox.SetAutoDeleteTime(requestPoint->GetAutoDeletedTime());
        requestBox.SetFinishTime(requestPoint->GetFinishDeadLine());
        requestBox.SetNotificationHashCode(request->GetKey());
        requestBox.SetSlotType(static_cast<int32_t>(requestPoint->GetSlotType()));
        requestBox.SetContentType(static_cast<int32_t>(requestPoint->GetNotificationType()));
        requestBox.SetReminderFlag(requestPoint->GetFlags()->GetReminderFlags());
        if (request->GetBundleName().empty()) {
            requestBox.SetCreatorBundleName(request->GetCreateBundle());
        } else {
            requestBox.SetCreatorBundleName(request->GetBundleName());
        }
        if (requestPoint->GetBigIcon() != nullptr) {
            requestBox.SetBigIcon(requestPoint->GetBigIcon());
        }
        if (requestPoint->GetOverlayIcon() != nullptr) {
            requestBox.SetOverlayIcon(requestPoint->GetOverlayIcon());
        }
        if (requestPoint->IsCommonLiveView()) {
            std::vector<uint8_t> buffer;
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewEncodeContent(requestPoint, buffer);
            requestBox.SetCommonLiveView(buffer);
        }
        SetNotificationContent(request->GetNotificationRequestPoint()->GetContent(),
            requestPoint->GetNotificationType(), requestBox);
        if (!requestBox.Serialize()) {
            ANS_LOGW("Dans OnConsumed serialize failed.");
            if (haCallback_ != nullptr) {
                haCallback_(PUBLISH_ERROR_EVENT_CODE, -1, BRANCH3_ID, "serialization failed");
            }
            return;
        }
        this->code_ = PUBLISH_ERROR_EVENT_CODE;
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
    code_ = DELETE_ERROR_EVENT_CODE;
    std::ostringstream keysStream;
    std::ostringstream slotTypesStream;
    for (auto notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
            continue;
        }
        ANS_LOGI("dans OnBatchCanceled %{public}s", notification->Dump().c_str());
        keysStream << GetNotificationKey(notification) << ' ';
        slotTypesStream << std::to_string(notification->GetNotificationRequestPoint()->GetSlotType()) << ' ';
    }
    std::string notificationKeys = keysStream.str();
    std::string slotTypes = slotTypesStream.str();

    std::function<void()> task = std::bind([peerDevice, notifications, notificationKeys, slotTypes]() {
        BatchRemoveNotificationBox batchRemoveBox;
        if (!notificationKeys.empty()) {
            batchRemoveBox.SetNotificationHashCode(notificationKeys);
        }
        batchRemoveBox.SetNotificationSlotTypes(slotTypes);

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
    code_ = DELETE_ERROR_EVENT_CODE;
    std::string notificationKey = GetNotificationKey(notification);
    std::function<void()> task = std::bind([peerDevice, notification, notificationKey]() {
        NotificationRemoveBox removeBox;
        ANS_LOGI("dans OnCanceled %{public}s", notification->Dump().c_str());
        removeBox.SetNotificationHashCode(notificationKey);
        removeBox.setNotificationSlotType(notification->GetNotificationRequestPoint()->GetSlotType());
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

ErrCode DistributedService::OnResponse(
    const std::shared_ptr<Notification>& notification, const DistributedDeviceInfo& device)
{
    this->code_ = MODIFY_ERROR_EVENT_CODE;
    NotificationResponseBox responseBox;
    ANS_LOGI("dans OnResponse %{public}s", notification->Dump().c_str());
    if (notification == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    auto hashCode = notification->GetKey();
    if (hashCode.find(DISTRIBUTED_LABEL) == 0) {
        hashCode.erase(0, DISTRIBUTED_LABEL.length());
    }

    responseBox.SetNotificationHashCode(hashCode);
    if (!responseBox.Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return ERR_ANS_NO_MEMORY;
    }
    auto result = DistributedClient::GetInstance().SendMessage(responseBox.GetByteBuffer(), responseBox.GetByteLength(),
        TransDataType::DATA_TYPE_MESSAGE, device.deviceId_, device.deviceType_);
    if (result != ERR_OK) {
        ANS_LOGE("dans OnResponse send message failed result: %{public}d", result);
        result = ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}
}
}
