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

#include "distributed_subscriber.h"

#include "ans_log_wrapper.h"
#include "distributed_service.h"
#include "notification_config_parse.h"
#include "distributed_preferences.h"

namespace OHOS {
namespace Notification {

DistribuedSubscriber::~DistribuedSubscriber()
{
}

void DistribuedSubscriber::OnDied()
{
    ANS_LOGW("Subscriber on died %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
}

void DistribuedSubscriber::OnConnected()
{
    ANS_LOGI("Subscriber on connected %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
}

void DistribuedSubscriber::OnDisconnected()
{
    ANS_LOGI("Subscriber on disconnected %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
}

void DistribuedSubscriber::OnCanceled(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGI("Subscriber on canceled %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
    if (deleteReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE) {
        ANS_LOGD("is cross device deletion");
        return;
    }
    if (CheckNeedCollaboration(request)) {
        DistributedService::GetInstance().OnCanceled(request, peerDevice_);
    }
}

void DistribuedSubscriber::OnConsumed(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGI("Subscriber on consumed %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        ANS_LOGI("No need consumed notification %{public}d %{public}s.",
            localDevice_.deviceType_, localDevice_.deviceId_.c_str());
        return;
    }
    DistributedService::GetInstance().OnConsumed(request, peerDevice_);
}

void DistribuedSubscriber::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGI("Subscriber on update.");
}

void DistribuedSubscriber::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
}

void DistribuedSubscriber::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
}

void DistribuedSubscriber::OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
}

void DistribuedSubscriber::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
}

void DistribuedSubscriber::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGI("Subscriber on batch canceled %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, peerDevice_.deviceId_.c_str(), localDevice_.deviceType_,
        localDevice_.deviceId_.c_str());
    if (deleteReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE) {
        ANS_LOGD("is cross device deletion");
        return;
    }
    std::vector<std::shared_ptr<Notification>> notifications;
    for (auto notification : requestList) {
        if (CheckNeedCollaboration(notification)) {
            notifications.push_back(notification);
        }
    }
    if (!notifications.empty()) {
        DistributedService::GetInstance().OnBatchCanceled(notifications, peerDevice_);
    }
}

void DistribuedSubscriber::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    ANS_LOGI("Notify changed %{public}s %{public}u.", bundleName.c_str(), localDevice_.deviceType_);
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }
    DistributedService::GetInstance().HandleBundleChanged(bundleName, false);
}

void DistribuedSubscriber::SetLocalDevice(DistributedDeviceInfo localDevice)
{
    localDevice_ = localDevice;
}

void DistribuedSubscriber::SetPeerDevice(DistributedDeviceInfo peerDevice)
{
    peerDevice_ = peerDevice;
}

bool DistribuedSubscriber::CheckCollaborativeRemoveType(const NotificationConstant::SlotType& slotType)
{
    std::string type;
    switch (slotType) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            type = "SOCIAL_COMMUNICATION";
            break;
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            type = "SERVICE_REMINDER";
            break;
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            type = "CONTENT_INFORMATION";
            break;
        case NotificationConstant::SlotType::OTHER:
            type = "OTHER";
            break;
        case NotificationConstant::SlotType::CUSTOM:
            type = "CUSTOM";
            break;
        case NotificationConstant::SlotType::LIVE_VIEW:
            type = "LIVE_VIEW";
            break;
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            type = "CUSTOMER_SERVICE";
            break;
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            type = "EMERGENCY_INFORMATION";
            break;
        case NotificationConstant::SlotType::ILLEGAL_TYPE:
            type = "ILLEGAL_TYPE";
            break;
        default:
            return false;
    }
    auto collaboratives = NotificationConfigParse::GetInstance()->GetCollaborativeDeleteType();
    return collaboratives.find(type) != collaboratives.end();
}

bool DistribuedSubscriber::CheckNeedCollaboration(const std::shared_ptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or request is nullptr");
        return false;
    }
    if (!CheckCollaborativeRemoveType(notification->GetNotificationRequestPoint()->GetSlotType())) {
        ANS_LOGE("CheckCollaborativeRemoveType failed");
        return false;
    }
    return true;
}
}
}