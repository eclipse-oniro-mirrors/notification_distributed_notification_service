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
}

void DistribuedSubscriber::SetLocalDevice(DistributedDeviceInfo localDevice)
{
    localDevice_ = localDevice;
}

void DistribuedSubscriber::SetPeerDevice(DistributedDeviceInfo peerDevice)
{
    peerDevice_ = peerDevice;
}

}
}
