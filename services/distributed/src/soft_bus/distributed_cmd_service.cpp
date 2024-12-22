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
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distributed_observer_service.h"
#include "distributed_device_data.h"
#include "dm_device_info.h"
#include "match_box.h"
#include "distributed_timer_service.h"

namespace OHOS {
namespace Notification {

std::string TransDeviceTypeIdToName(uint16_t deviceType)
{
    switch (deviceType) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "wearable";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return "Pad";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE: {
            return "Phone";
        }
        default:
            return "";
    }
}

namespace {
constexpr uint32_t DEFAULT_LOCK_SCREEN_FLAG = 2;
}

void DistributedService::SetCurrentUserId(int32_t userId)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, userId]() {
        userId_ = userId;
        for (auto& subscriberItem : subscriberMap_) {
            sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
            subscribeInfo->AddAppUserId(userId_);
            int result = NotificationHelper::SubscribeNotification(subscriberItem.second, subscribeInfo);
            if (result != 0) {
                ANS_LOGW("Dans subscribe failed %{public}d %{public}s", result, subscriberItem.first.c_str());
            }
        }
        ANS_LOGI("Dans set current userId %{public}d %{public}u", userId_, subscriberMap_.size());
    });
    serviceQueue_->submit(task);
}

void DistributedService::InitDeviceState(const DistributedDeviceInfo device)
{
    if (device.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        uint32_t state = OberverService::GetInstance().IsScreenLocked();
        SyncDeviceState(state);
    }
}

void DistributedService::HandleDeviceState(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t state;
    std::string deviceName;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceType(deviceName) || !stateBox.GetState(state)) {
        ANS_LOGW("Dans unbox state failed.");
        return;
    }
    uint32_t status = (static_cast<uint32_t>(state) << 1);
    int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, status, DEFAULT_LOCK_SCREEN_FLAG);
    ANS_LOGI("Dans set state %{public}s %{public}u.", deviceName.c_str(), state);
}

void DistributedService::SyncDeviceState(int32_t state)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, state]() {
        NotifticationStateBox stateBox;
        stateBox.SetState(state);
        stateBox.SetDeviceType(TransDeviceTypeIdToName(localDevice_.deviceType_));
        if (!stateBox.Serialize()) {
            ANS_LOGW("Dans SyncDeviceState serialize failed.");
            return;
        }
        for (const auto& peer : peerDevice_) {
            DistributedClient::GetInstance().SendMessage(stateBox.GetByteBuffer(),
                stateBox.GetByteLength(), TransDataType::DATA_TYPE_MESSAGE,
                peer.second.deviceId_, peer.second.deviceType_);
            ANS_LOGI("Dans SyncDeviceState %{public}d %{public}d %{public}d %{public}u.",
                peer.second.deviceType_, localDevice_.deviceType_, state, peerDevice_.size());
        }
    });
    serviceQueue_->submit(task);
}

void DistributedService::SyncDeviceMatch(const DistributedDeviceInfo peerDevice, MatchType type)
{
    NotifticationMatchBox matchBox;
    matchBox.SetVersion(CURRENT_VERSION);
    matchBox.SetMatchType(type);
    matchBox.SetLocalDeviceId(localDevice_.deviceId_);
    matchBox.SetLocalDeviceType(localDevice_.deviceType_);
    if (type == MatchType::MATCH_ACK) {
        matchBox.SetPeerDeviceId(peerDevice.deviceId_);
        matchBox.SetPeerDeviceType(peerDevice.deviceType_);
    }
    if (!matchBox.Serialize()) {
        ANS_LOGW("Dans SyncDeviceMatch serialize failed.");
        return;
    }
    DistributedClient::GetInstance().SendMessage(matchBox.GetByteBuffer(),
        matchBox.GetByteLength(), TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, peerDevice.deviceType_);
    ANS_LOGI("Dans SyncDeviceMatch %{public}s %{public}d %{public}s %{public}d %{public}d.",
        peerDevice.deviceId_.c_str(), peerDevice.deviceType_, localDevice_.deviceId_.c_str(),
        localDevice_.deviceType_, type);
}

void DistributedService::HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t type = 0;
    DistributedDeviceInfo peerDevice;
    NotifticationMatchBox matchBox = NotifticationMatchBox(boxMessage);
    if (!matchBox.GetLocalDeviceType(type)) {
        ANS_LOGI("Dans handle match device type failed.");
        return;
    } else {
        peerDevice.deviceType_ = static_cast<uint16_t>(type);
    }
    if (!matchBox.GetLocalDeviceId(peerDevice.deviceId_)) {
        ANS_LOGI("Dans handle match device id failed.");
        return;
    }
    int32_t matchType = 0;
    if (!matchBox.GetMatchType(matchType)) {
        ANS_LOGI("Dans handle match sync failed.");
        return;
    }
    ANS_LOGI("Dans handle match device type %{public}d.", matchType);
    if (matchType == MatchType::MATCH_SYN) {
        SyncDeviceMatch(peerDevice, MatchType::MATCH_ACK);
    } else if (matchType == MatchType::MATCH_ACK) {
        SubscribeNotifictaion(peerDevice);
    }
}
}
}
