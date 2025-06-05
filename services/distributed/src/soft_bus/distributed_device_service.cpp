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
#include "distributed_observer_service.h"

namespace OHOS {
namespace Notification {

static const int32_t MAX_CONNECTED_TYR = 5;
static const uint32_t DEFAULT_LOCK_SCREEN_FLAG = 2;

DistributedDeviceService& DistributedDeviceService::GetInstance()
{
    static DistributedDeviceService distributedDeviceService;
    return distributedDeviceService;
}

std::string DistributedDeviceService::DeviceTypeToTypeString(uint16_t deviceType)
{
    switch (deviceType) {
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH: {
            return "wearable";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return "pad";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PC: {
            return "pc";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1: {
            return "pc";
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE: {
            return "phone";
        }
        default:
            return "";
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

bool DistributedDeviceService::IsReportDataByHa()
{
    return localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
}

void DistributedDeviceService::SetSubscribeAllConnect(bool subscribe)
{
    subscribeAllConnect = subscribe;
}

bool DistributedDeviceService::IsSubscribeAllConnect()
{
    return subscribeAllConnect;
}

bool DistributedDeviceService::CheckNeedSubscribeAllConnect()
{
    std::lock_guard<std::mutex> lock(mapLock_);
    for (auto& device : peerDevice_) {
        if (device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD ||
            device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1 ||
            device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PC) {
            return true;
        }
    }
    return false;
}

bool DistributedDeviceService::IsSyncLiveView(const std::string& deviceId, bool forceSync)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device is data %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }

    if (iter->second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PC ||
        iter->second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1) {
        ANS_LOGI("Dans device pc no need sync %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    if (iter->second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD) {
        if (!iter->second.deviceUsage || iter->second.peerState_ != DeviceState::STATE_SYNC) {
            return false;
        }
    }

    if (!forceSync && iter->second.liveViewSync) {
        ANS_LOGI("Dans live view sync %{public}d %{public}d.", forceSync, iter->second.liveViewSync);
        return false;
    }
    return true;
}

bool DistributedDeviceService::IsSyncIcons(const std::string& deviceId, bool forceSync)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device is data %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    if (iter->second.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        return false;
    }

    if (!forceSync && iter->second.iconSync) {
        ANS_LOGI("Dans icon sync %{public}d %{public}d.", forceSync, iter->second.iconSync);
        return false;
    }
    return true;
}

bool DistributedDeviceService::IsSyncInstalledBundle(const std::string& deviceId, bool forceSync)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device is data %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }

    if (iter->second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        return false;
    }

    if (!forceSync && iter->second.installedBunlesSync) {
        ANS_LOGI("Dans bundle sync %{public}d %{public}d.", forceSync, iter->second.installedBunlesSync);
        return false;
    }
    return true;
}

void DistributedDeviceService::SetDeviceSyncData(const std::string& deviceId, int32_t type, bool syncData)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device set data %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    if (type == SYNC_BUNDLE_ICONS) {
        iter->second.iconSync = syncData;
    }
    if (type == SYNC_LIVE_VIEW) {
        iter->second.liveViewSync = syncData;
    }
    if (type == SYNC_INSTALLED_BUNDLE) {
        iter->second.installedBunlesSync = syncData;
    }
    if (type == DEVICE_USAGE) {
        iter->second.deviceUsage = syncData;
    }
}

void DistributedDeviceService::SetDeviceState(const std::string& deviceId, int32_t state)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device set status %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.peerState_ = state;
}

bool DistributedDeviceService::CheckDeviceExist(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    if (peerDevice_.find(deviceId) == peerDevice_.end()) {
        ANS_LOGI("Dans unknown device %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    return true;
}

bool DistributedDeviceService::GetDeviceInfo(const std::string& deviceId, DistributedDeviceInfo& device)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    device = iter->second;
    return true;
}

bool DistributedDeviceService::CheckDeviceNeedSync(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device connected %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    if (iter->second.connectedTry_ >= MAX_CONNECTED_TYR || iter->second.peerState_ != DeviceState::STATE_SYNC) {
        ANS_LOGI("Dans no need try %{public}d %{public}d.", iter->second.connectedTry_,
            iter->second.peerState_);
        iter->second.connectedTry_ = 0;
        return false;
    }
    return true;
}

void DistributedDeviceService::IncreaseDeviceSyncCount(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device count %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.connectedTry_ = iter->second.connectedTry_ + 1;
    ANS_LOGI("Dans sync device count %{public}s %{public}d.", StringAnonymous(deviceId).c_str(),
        iter->second.connectedTry_);
}

void DistributedDeviceService::AddDeviceInfo(DistributedDeviceInfo deviceItem)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    peerDevice_[deviceItem.deviceId_] = deviceItem;
}

void DistributedDeviceService::DeleteDeviceInfo(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto deviceIter = peerDevice_.find(deviceId);
    if (deviceIter != peerDevice_.end()) {
        ANS_LOGI("Delete device %{public}s.", StringAnonymous(deviceId).c_str());
        peerDevice_.erase(deviceId);
    }
}

std::map<std::string, DistributedDeviceInfo>& DistributedDeviceService::GetDeviceList()
{
    std::lock_guard<std::mutex> lock(mapLock_);
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
    std::string deviceId;
    std::string deviceName;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceId(deviceId) || !stateBox.GetDeviceType(deviceName)) {
        ANS_LOGW("Dans unbox deviceId and name failed.");
        return;
    }

    int32_t status;
    if (stateBox.GetState(status)) {
        int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, status,
            DEFAULT_LOCK_SCREEN_FLAG, deviceId);
        ANS_LOGI("Dans set state %{public}s %{public}s %{public}d %{public}d.", deviceName.c_str(),
            StringAnonymous(deviceId).c_str(), status, result);
    }

    bool liveViewEnable;
    bool notificationEnable;
    if (stateBox.GetLiveViewEnable(liveViewEnable) && stateBox.GetNotificationEnable(notificationEnable)) {
        int32_t result = NotificationHelper::SetTargetDeviceSwitch(deviceName, deviceId,
            notificationEnable, liveViewEnable);
        ANS_LOGI("Dans set enable %{public}s %{public}s %{public}d %{public}d %{public}d.", deviceName.c_str(),
            StringAnonymous(deviceId).c_str(), liveViewEnable, notificationEnable, result);
    }
}
#else
void DistributedDeviceService::InitCurrentDeviceStatus()
{
    bool notificationEnable = true;
    bool liveViewEnable = false;
    std::string localType = DeviceTypeToTypeString(localDevice_.deviceType_);
    int32_t status = OberverService::GetInstance().IsScreenLocked();
    auto result = NotificationHelper::IsDistributedEnabledBySlot(NotificationConstant::SlotType::LIVE_VIEW,
        localType, liveViewEnable);
    if (result != ERR_OK) {
        ANS_LOGW("Dans get live view enable failed.");
    }
    SyncDeviceStatus(STATE_TYPE_BOTH, status, notificationEnable, liveViewEnable);
}

void DistributedDeviceService::SyncDeviceStatus(int32_t type, int32_t status,
    bool notificationEnable, bool liveViewEnable)
{
    std::shared_ptr<NotifticationStateBox> stateBox = std::make_shared<NotifticationStateBox>();
    stateBox->SetDeviceType(DeviceTypeToTypeString(localDevice_.deviceType_));
    stateBox->SetDeviceId(localDevice_.deviceId_);
    if (type == STATE_TYPE_LOCKSCREEN || type == STATE_TYPE_BOTH) {
        stateBox->SetState(status);
    }
    if (type == STATE_TYPE_SWITCH || type == STATE_TYPE_BOTH) {
        stateBox->SetLiveViewEnable(liveViewEnable);
        stateBox->SetNotificationEnable(notificationEnable);
    }

    if (!stateBox->Serialize()) {
        ANS_LOGW("Dans SyncDeviceState serialize failed.");
        return;
    }
    std::lock_guard<std::mutex> lock(mapLock_);
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

