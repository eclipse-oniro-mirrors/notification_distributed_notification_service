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

#include "distributed_subscribe_service.h"

#include "analytics_util.h"
#include "os_account_manager.h"
#include "distributed_data_define.h"
#include "notification_helper.h"
#include "distributed_device_service.h"
#include "notification_subscribe_info.h"

namespace OHOS {
namespace Notification {

const int32_t FILTER_IM_TYPE = 1;
const int32_t FILTER_IM_REPLY_TYPE = 2;

static std::string SubscribeTransDeviceType(uint16_t deviceType)
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

int32_t DistributedSubscribeService::GetCurrentActiveUserId()
{
    int32_t userId = DEFAULT_USER_ID;
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        ANS_LOGW("Dans get Current userId failed %{public}d.", ret);
        return DEFAULT_USER_ID;
    }
    return userId;
}

DistributedSubscribeService& DistributedSubscribeService::GetInstance()
{
    static DistributedSubscribeService distributedSubscribeService;
    return distributedSubscribeService;
}

void DistributedSubscribeService::SubscribeNotification(const DistributedDeviceInfo device)
{
    DistributedDeviceInfo peerDevice;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(device.deviceId_, peerDevice)) {
        ANS_LOGI("Local device no %{public}s .", StringAnonymous(device.deviceId_).c_str());
        return;
    }

    int32_t userId = GetCurrentActiveUserId();
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    subscriber->SetLocalDevice(DistributedDeviceService::GetInstance().GetLocalDevice());
    subscriber->SetPeerDevice(peerDevice);
    sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    if (peerDevice.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        std::vector<NotificationConstant::SlotType> slotTypes;
        slotTypes.push_back(NotificationConstant::SlotType::LIVE_VIEW);
        slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        subscribeInfo->SetSlotTypes(slotTypes);
        subscribeInfo->SetFilterType(FILTER_IM_TYPE);
    }
    subscribeInfo->AddDeviceType(DistributedDeviceService::DeviceTypeToTypeString(peerDevice.deviceType_));
    subscribeInfo->AddAppUserId(userId);
    subscribeInfo->SetNeedNotifyApplication(true);
    subscribeInfo->SetNeedNotifyResponse(true);
    int result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        std::lock_guard<ffrt::mutex> lock(mapLock_);
        auto iter = subscriberMap_.find(peerDevice.deviceId_);
        if (iter != subscriberMap_.end()) {
            NotificationHelper::UnSubscribeNotification(iter->second);
        }
        subscriberMap_[peerDevice.deviceId_] = subscriber;
        DistributedDeviceService::GetInstance().SetDeviceState(peerDevice.deviceId_, DeviceState::STATE_ONLINE);
        std::string reason = "deviceType: " + std::to_string(peerDevice.deviceType_) +
            " ; deviceId: " + StringAnonymous(peerDevice.deviceId_);
        AnalyticsUtil::GetInstance().SendHaReport(PUBLISH_ERROR_EVENT_CODE, 0, BRANCH3_ID, reason);
    }
    ANS_LOGI("Subscribe notification %{public}s %{public}d %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_, userId, result);
}

void DistributedSubscribeService::UnSubscribeNotification(const std::string &deviceId, uint16_t deviceType,
    bool releaseDevice)
{
    if (releaseDevice) {
        DistributedDeviceService::GetInstance().DeleteDeviceInfo(deviceId);
    }
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iter = subscriberMap_.find(deviceId);
    if (iter == subscriberMap_.end()) {
        ANS_LOGI("UnSubscribe invalid %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }

    int32_t result = NotificationHelper::UnSubscribeNotification(iter->second);
    if (result == ERR_OK) {
        subscriberMap_.erase(deviceId);
    }
    std::string message = "UnSubscribe: " + StringAnonymous(deviceId) + " type: " + std::to_string(deviceType);
    AnalyticsUtil::GetInstance().SendHaReport(OPERATION_DELETE_BRANCH, result, BRANCH2_ID, message,
        PUBLISH_ERROR_EVENT_CODE);
    ANS_LOGI("UnSubscribe notification %{public}s %{public}d.", StringAnonymous(deviceId).c_str(), deviceType);
}

void DistributedSubscribeService::UnSubscribeAllNotification()
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto& subscriberInfo : subscriberMap_) {
        int32_t result = NotificationHelper::UnSubscribeNotification(subscriberInfo.second);
        ANS_LOGI("UnSubscribe %{public}s %{public}d.", subscriberInfo.first.c_str(), result);
    }
}

}
}

