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
#include "distributed_screenlock_service.h"
#include "distributed_device_data.h"
#include "dm_device_info.h"

namespace OHOS {
namespace Notification {

std::string TransDeviceTypeIdToName(uint16_t deviceType)
{
    switch (deviceType) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "Watch";
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

void DistributedService::InitDeviceState(const DistributedDeviceInfo peerDevice)
{
    if (peerDevice.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE &&
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        uint32_t state = ScreenLockService::GetInstance().IsScreenLocked();
        SyncDeviceState(state);
    }
}

void DistributedService::SetDeviceState(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t state;
    std::string deviceName;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceType(deviceName) || !stateBox.GetState(state)) {
        ANS_LOGW("Dans unbox state failed.");
        return;
    }
    std::function<void()> task = std::bind([deviceName, state]() {
        int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, static_cast<uint32_t>(state));
        ANS_LOGI("Dans set state %{public}s %{public}u.", deviceName.c_str(), state);
    });
    serviceQueue_->submit(task);
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
            ANS_LOGI("Dans SyncDeviceState %{public}d %{public}d %{public}d %{public}lu.",
                peer.second.deviceType_, localDevice_.deviceType_, state, peerDevice_.size());
        }
    });
    serviceQueue_->submit(task);
}

}
}
