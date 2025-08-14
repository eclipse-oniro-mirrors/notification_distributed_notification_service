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
#include "distributed_service.h"
#include "distributed_send_adapter.h"

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
            return DistributedService::WEARABLE_DEVICE_TYPE;
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD: {
            return DistributedService::PAD_DEVICE_TYPE;
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PC: {
            return DistributedService::PC_DEVICE_TYPE;
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1: {
            return DistributedService::PC_DEVICE_TYPE;
        }
        case DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE: {
            return DistributedService::PHONE_DEVICE_TYPE;
        }
        default:
            return "";
    }
}

static std::string DeviceTypeConversion(const std::string& deviceType)
{
    if (deviceType == DistributedService::PAD_DEVICE_TYPE) {
        return "pad";
    }

    if (deviceType == DistributedService::PC_DEVICE_TYPE) {
        return "pc";
    }
    return deviceType;
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

bool DistributedDeviceService::IsLocalPadOrPC()
{
    return localDevice_.IsPadOrPc();
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto& device : peerDevice_) {
        if (device.second.IsPadOrPc()) {
            return true;
        }
    }
    return false;
}

bool DistributedDeviceService::IsSyncLiveView(const std::string& deviceId, bool forceSync)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
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
        if (!iter->second.deviceUsage || iter->second.peerState_ == DeviceState::STATE_SYNC) {
            ANS_LOGI("Dans pad sync %{public}d %{public}d.", iter->second.peerState_,
                iter->second.deviceUsage);
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device is data %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }

    if (iter->second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        return false;
    }

    if (!forceSync && iter->second.installedBundlesSync) {
        ANS_LOGI("Dans bundle sync %{public}d %{public}d.", forceSync, iter->second.installedBundlesSync);
        return false;
    }
    return true;
}

void DistributedDeviceService::SetDeviceSyncData(const std::string& deviceId, int32_t type, bool syncData)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
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
        iter->second.installedBundlesSync = syncData;
    }
    if (type == DEVICE_USAGE) {
        iter->second.deviceUsage = syncData;
    }
}

void DistributedDeviceService::ResetDeviceInfo(const std::string& deviceId, int32_t peerState)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto deviceIter = peerDevice_.find(deviceId);
    if (deviceIter == peerDevice_.end()) {
        ANS_LOGI("Dans unknown device %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    deviceIter->second.connectedTry_ = 0;
    deviceIter->second.deviceUsage = false;
    deviceIter->second.liveViewSync = false;
    deviceIter->second.iconSync = false;
    deviceIter->second.installedBundlesSync = false;
    deviceIter->second.peerState_ = peerState;
}

void DistributedDeviceService::SetDeviceState(const std::string& deviceId, int32_t state)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGE("Dans unknown device set status %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    iter->second.peerState_ = state;
}

bool DistributedDeviceService::CheckDeviceExist(const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    if (peerDevice_.find(deviceId) == peerDevice_.end()) {
        ANS_LOGI("Dans unknown device %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    return true;
}

bool DistributedDeviceService::GetDeviceInfo(const std::string& deviceId, DistributedDeviceInfo& device)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(deviceId).c_str());
        return false;
    }
    device = iter->second;
    return true;
}

bool DistributedDeviceService::GetDeviceInfoByUdid(const std::string& udid, DistributedDeviceInfo& device)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto deviceItem : peerDevice_) {
        if (udid == deviceItem.second.udid_) {
            device = deviceItem.second;
            return true;
        }
    }
    ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(udid).c_str());
    return false;
}

bool DistributedDeviceService::CheckDeviceNeedSync(const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    peerDevice_[deviceItem.deviceId_] = deviceItem;
}

void DistributedDeviceService::DeleteDeviceInfo(const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto deviceIter = peerDevice_.find(deviceId);
    if (deviceIter != peerDevice_.end()) {
        ANS_LOGI("Delete device %{public}s.", StringAnonymous(deviceId).c_str());
        peerDevice_.erase(deviceId);
    }
}

std::map<std::string, DistributedDeviceInfo>& DistributedDeviceService::GetDeviceList()
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    return peerDevice_;
}

void DistributedDeviceService::GetDeviceList(std::map<std::string, DistributedDeviceInfo>& peerDevices)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto deviceItem : peerDevice_) {
        peerDevices[deviceItem.first] = deviceItem.second;
    }
}

void DistributedDeviceService::SyncDeviceMatch(const DistributedDeviceInfo peerDevice, MatchType type)
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
        return;
    }

    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(matchBox, peerDevice,
        TransDataType::DATA_TYPE_MESSAGE, MODIFY_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
    ANS_LOGI("Dans SyncDeviceMatch %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_);
}

#ifdef DISTRIBUTED_FEATURE_MASTER
void DistributedDeviceService::SetDeviceStatus(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::string deviceId;
    NotifticationStateBox stateBox = NotifticationStateBox(boxMessage);
    if (!stateBox.GetDeviceId(deviceId)) {
        ANS_LOGW("Dans unbox deviceId and name failed.");
        return;
    }

    DistributedDeviceInfo device;
    if (!GetDeviceInfo(deviceId, device)) {
        ANS_LOGW("Dans get device failed %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    int32_t status;
    std::string deviceName = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
    if (stateBox.GetState(status)) {
        int32_t result = NotificationHelper::SetTargetDeviceStatus(deviceName, status,
            DEFAULT_LOCK_SCREEN_FLAG, device.udid_);
        ANS_LOGI("Dans set state %{public}s %{public}s %{public}d %{public}d.", deviceName.c_str(),
            StringAnonymous(deviceId).c_str(), status, result);
    }

    bool liveViewEnable;
    bool notificationEnable;
    if (stateBox.GetLiveViewEnable(liveViewEnable) && stateBox.GetNotificationEnable(notificationEnable)) {
        int32_t result = NotificationHelper::SetTargetDeviceSwitch(deviceName, device.udid_,
            notificationEnable, liveViewEnable);
        ANS_LOGI("Dans set enable %{public}s %{public}s %{public}d %{public}d %{public}d.", deviceName.c_str(),
            StringAnonymous(deviceId).c_str(), liveViewEnable, notificationEnable, result);
    }
}
#else
void DistributedDeviceService::InitCurrentDeviceStatus()
{
    bool notificationEnable = false;
    bool liveViewEnable = false;
    std::string localType = DeviceTypeToTypeString(localDevice_.deviceType_);
    int32_t status = OberverService::GetInstance().IsScreenLocked();
    auto result = NotificationHelper::IsDistributedEnabledBySlot(NotificationConstant::SlotType::LIVE_VIEW,
        localType, liveViewEnable);
    if (result != ERR_OK) {
        ANS_LOGW("Dans get live view enable failed.");
    }
    result = NotificationHelper::IsDistributedEnabled(localType, notificationEnable);
    if (result != ERR_OK) {
        ANS_LOGW("Dans get notification enable failed.");
    }
    SyncDeviceStatus(STATE_TYPE_BOTH, status, notificationEnable, liveViewEnable);
}

void DistributedDeviceService::SyncDeviceStatus(int32_t type, int32_t status,
    bool notificationEnable, bool liveViewEnable)
{
    std::shared_ptr<NotifticationStateBox> stateBox = std::make_shared<NotifticationStateBox>();
    std::string deviceType = DeviceTypeToTypeString(localDevice_.deviceType_);
    deviceType = DeviceTypeConversion(deviceType);
    stateBox->SetDeviceType(deviceType);
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
    bool isPad = IsLocalPadOrPC();
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (const auto& peer : peerDevice_) {
        if (isPad && peer.second.peerState_ != DeviceState::STATE_ONLINE) {
            ANS_LOGI("DeviceState %{public}d %{public}d %{public}d %{public}d %{public}s.",
                status, notificationEnable, liveViewEnable, peer.second.deviceType_,
                StringAnonymous(peer.second.deviceId_).c_str());
            continue;
        }
        std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(stateBox, peer.second,
            TransDataType::DATA_TYPE_MESSAGE, MODIFY_ERROR_EVENT_CODE);
        DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
        ANS_LOGI("DeviceState %{public}d %{public}d %{public}d %{public}d %{public}lu.",
            type, status, liveViewEnable, notificationEnable, peerDevice_.size());
    }
}
#endif
}
}

