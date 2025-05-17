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

#include "distributed_device_service.h"

#include "state_box.h"
#include "analytics_util.h"
#include "distributed_client.h"
#include "distributed_data_define.h"
#include "distributed_device_data.h"
#include "notification_helper.h"

namespace OHOS {
namespace Notification {

static const int32_t MAX_CONNECTED_TYR = 5;
static const uint32_t DEFAULT_LOCK_SCREEN_FLAG = 2;

DistributedDeviceService& DistributedDeviceService::GetInstance()
{
    static DistributedDeviceService distributedDeviceService;
    return distributedDeviceService;
}

std::string DeviceTypeToTypeString(uint16_t deviceType)
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
            return std::string();
    }
}

void DistributedDeviceService::InitLocalDevice(const std::string &deviceId, uint16_t deviceType)
{
    localDevice_.deviceId_ = deviceId;
    localDevice_.deviceType_ = deviceType;
}

DistributedDeviceInfo DistributedDeviceService::GetLocalDevice()
{
    return localDevice_;
}

bool DistributedDeviceService::IsDeviceSyncData(const std::string& deviceId)
{
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device is data %{public}s.", StringAnonymous(deviceId).c_str());
        return true;
    }
    return iter->second.isSync;
}

void DistributedDeviceService::SetDeviceSyncData(const std::string& deviceId, bool syncData)
{
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device set data %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.isSync = true;
}

void DistributedDeviceService::SetDeviceState(const std::string& deviceId, int32_t state)
{
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device set status %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.peerState_ = state;
}

bool DistributedDeviceService::CheckDeviceExist(const std::string& deviceId)
{
    if (peerDevice_.find(deviceId) == peerDevice_.end()) {
        ANS_LOGI("Dans unknown device %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    return true;
}

bool DistributedDeviceService::CheckDeviceNeedSync(const std::string& deviceId)
{
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device connected %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    if (iter->second.connectedTry_ >= MAX_CONNECTED_TYR || iter->second.peerState_ != DeviceState::STATE_SYNC) {
        ANS_LOGE("Dans no need try %{public}d.", iter->second.connectedTry_);
        iter->second.connectedTry_ = 0;
        return false;
    }
    return true;
}

void DistributedDeviceService::IncreaseDeviceSyncCount(const std::string& deviceId)
{
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device count %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.connectedTry_ = iter->second.connectedTry_ + 1;
}

void DistributedDeviceService::AddDeviceInfo(DistributedDeviceInfo deviceItem)
{
    peerDevice_[deviceItem.deviceId_] = deviceItem;
}

void DistributedDeviceService::DeleteDeviceInfo(const std::string& deviceId)
{
    auto deviceIter = peerDevice_.find(deviceId);
    if (deviceIter != peerDevice_.end()) {
        ANS_LOGI("Delete device %{public}s.", StringAnonymous(deviceId).c_str());
        peerDevice_.erase(deviceId);
    }
}

std::map<std::string, DistributedDeviceInfo>& DistributedDeviceService::GetDeviceList()
{
    return peerDevice_;
}

int32_t DistributedDeviceService::SyncDeviceMatch(const DistributedDeviceInfo peerDevice, MatchType type)
{
    std::shared_ptr<NotifticationMatchBox> matchBox = std::make_shared<NotifticationMatchBox>();
    matchBox->SetVersion(CURRENT_VERSION);
    matchBox->SetMatchType(type);
    matchBox->SetLocalDeviceId(localDevice_.deviceId_);
    matchBox->SetLocalDeviceType(localDevice_.deviceType_);
    if (type == MatchType::MATCH_ACK) {
        matchBox->SetPeerDeviceId(peerDevice.deviceId_);
        matchBox->SetPeerDeviceType(peerDevice.deviceType_);
    }
    if (!matchBox->Serialize()) {
        ANS_LOGW("Dans SyncDeviceMatch serialize failed.");
        return -1;
    }
    int32_t result = DistributedClient::GetInstance().SendMessage(matchBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, MODIFY_ERROR_EVENT_CODE);
    ANS_LOGI("Dans SyncDeviceMatch %{public}s %{public}d %{public}s %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), localDevice_.deviceType_, type);
    return result;
}

#ifdef DISTRIBUTED_FEATURE_MASTER
void DistributedDeviceService::SetDeviceStatus(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t status;
    std::string deviceName;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceType(deviceName) || !stateBox.GetState(status)) {
        ANS_LOGW("Dans unbox state failed.");
        return;
    }
    std::string deviceId;
    if (!stateBox.GetDeviceId(deviceId)) {
        ANS_LOGW("Dans unbox deviceId failed.");
    }
    int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, status,
        DEFAULT_LOCK_SCREEN_FLAG, deviceId);
    ANS_LOGI("Dans set state %{public}s %{public}d.", deviceName.c_str(), status);
}
#else
void DistributedDeviceService::SyncDeviceStatus(int32_t status)
{
    std::shared_ptr<NotifticationStateBox> stateBox = std::make_shared<NotifticationStateBox>();
    stateBox->SetState(status);
    stateBox->SetDeviceType(DeviceTypeToTypeString(localDevice_.deviceType_));
    stateBox->SetDeviceId(localDevice_.deviceId_);
    if (!stateBox->Serialize()) {
        ANS_LOGW("Dans SyncDeviceState serialize failed.");
        return;
    }
    for (const auto& peer : peerDevice_) {
        DistributedClient::GetInstance().SendMessage(stateBox, TransDataType::DATA_TYPE_MESSAGE,
            peer.second.deviceId_, MODIFY_ERROR_EVENT_CODE);
        ANS_LOGI("Dans SyncDeviceState %{public}d %{public}d %{public}d %{public}d.",
            peer.second.deviceType_, localDevice_.deviceType_, status, (int32_t)(peerDevice_.size()));
    }
}
#endif
}
}
