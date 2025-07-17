/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "distributed_device_status.h"

#include "distributed_data_define.h"
#include "distributed_extension_service.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace {
const static std::string WEARABLE = "wearable";
const static std::string LITEWEARABLE = "liteWearable";
}

DistributedDeviceStatus::DistributedDeviceStatus() = default;

DistributedDeviceStatus::~DistributedDeviceStatus() = default;

ErrCode DistributedDeviceStatus::SetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    uint32_t oldStatus = deviceStatus_.ReadVal(deviceType);
    for (uint32_t i = 0; i < STATUS_SIZE; i++) {
        if (((1 << i) & controlFlag) && ((1 << i) & status)) {
            oldStatus |= (1 << i);
        }
        if (((1 << i) & controlFlag) && !((1 << i) & status)) {
            oldStatus &= ~(1 << i);
        }
    }
    if (deviceType == LITEWEARABLE) {
        uint32_t wearableStatus = deviceStatus_.ReadVal(WEARABLE);
        for (uint32_t i = 0; i < STATUS_SIZE; i++) {
            if (((1 << i) & controlFlag) && ((1 << i) & status)) {
                wearableStatus |= (1 << i);
            }
            if (((1 << i) & controlFlag) && !((1 << i) & status)) {
                wearableStatus &= ~(1 << i);
            }
        }
        deviceStatus_.EnsureInsert(WEARABLE, wearableStatus);
        ANS_LOGI("update lite wearable status %{public}u %{public}u", wearableStatus, status);
    }
    deviceStatus_.EnsureInsert(deviceType, oldStatus);
    ANS_LOGI("update %{public}s status %{public}u %{public}u", deviceType.c_str(), oldStatus, status);
    return ERR_OK;
}

void ChangeStatus(DeviceStatus& device, const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, int32_t userId)
{
    uint32_t beforeStatus = device.status;
    if ((1 << DistributedDeviceStatus::USERID_FLAG) & controlFlag) {
        device.userId = userId;
    }
    for (uint32_t i = 0; i < DistributedDeviceStatus::STATUS_SIZE; i++) {
        if (((1 << i) & controlFlag) && ((1 << i) & status)) {
            device.status |= (1 << i);
        }
        if (((1 << i) & controlFlag) && !((1 << i) & status)) {
            device.status &= ~(1 << i);
        }
    }

    if (deviceType == NotificationConstant::PAD_DEVICE_TYPE ||
        deviceType == NotificationConstant::PC_DEVICE_TYPE) {
        DeviceStatueChangeInfo changeInfo;
        changeInfo.deviceId = device.deviceId;
        if (((1 << DistributedDeviceStatus::USING_FLAG) & controlFlag) &&
            ((1 << DistributedDeviceStatus::USING_FLAG) & device.status)) {
            changeInfo.changeType = DeviceStatueChangeType::DEVICE_USING_ONLINE;
            DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
            ANS_LOGI("notify %{public}s %{public}s using change.", device.deviceType.c_str(),
                StringAnonymous(device.deviceId).c_str());
        } else if (((1 << DistributedDeviceStatus::USING_FLAG) & device.status) == 0) {
            changeInfo.changeType = DeviceStatueChangeType::DEVICE_USING_CLOSE;
            DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
        }
    }

    ANS_LOGI("update %{public}s %{public}s %{public}d status %{public}d %{public}u %{public}u",
        device.deviceType.c_str(), StringAnonymous(device.deviceId).c_str(), userId, controlFlag,
        beforeStatus, device.status);
}

ErrCode DistributedDeviceStatus::SetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, const std::string deviceId, int32_t userId)
{
    bool existFlag = false;
    std::string deviceStatusId = deviceId;
    uint32_t finalStatus = 0;
    bool allConnect = ((1 << NETWORKID_FLAG) & controlFlag);
    if (allConnect) {
        std::string udid;
        int32_t result = DistributedExtensionService::GetInstance().TransDeviceIdToUdid(deviceId, udid);
        if (result != ERR_OK) {
            ANS_LOGI("Get udid failed %{public}s %{public}s %{public}d ", deviceType.c_str(),
                StringAnonymous(deviceStatusId).c_str(), result);
            return ERR_ANS_TASK_ERR;
        }
        deviceStatusId = udid;
    }

    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto device = deviceInfo_.begin(); device != deviceInfo_.end(); device++) {
        if (device->deviceType != deviceType || device->deviceId != deviceStatusId) {
            continue;
        }

        if (allConnect && ((1 << DistributedDeviceStatus::USING_FLAG) & device->status) == 0) {
            ANS_LOGI("No change %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceStatusId).c_str());
            continue;
        }
        ChangeStatus(*device, deviceType, status, controlFlag, userId);
        ANS_LOGI("update sttuas %{public}s %{public}u", StringAnonymous(device->deviceId).c_str(), device->status);
        existFlag = true;
        break;
    }

    // for allconnect release device
    if (allConnect) {
        ANS_LOGI("Not need %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceStatusId).c_str());
        return ERR_OK;
    }

    if (!existFlag) {
        DeviceStatus device = DeviceStatus(deviceType, deviceStatusId);
        ChangeStatus(device, deviceType, status, controlFlag, userId);
        deviceInfo_.emplace_back(device);
        ANS_LOGI("Add device %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceStatusId).c_str());
    }
    return ERR_OK;
}

uint32_t DistributedDeviceStatus::GetDeviceStatus(const std::string &deviceType)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    return deviceStatus_.ReadVal(deviceType);
}

DeviceStatus DistributedDeviceStatus::GetMultiDeviceStatus(
    const std::string &deviceType, const uint32_t status)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (DeviceStatus device : deviceInfo_) {
        if (device.deviceType == deviceType && (device.status & status) == status) {
            return device;
        }
    }
    return DeviceStatus("", "");
}
} // namespace Notification
} // namespace OHOS
