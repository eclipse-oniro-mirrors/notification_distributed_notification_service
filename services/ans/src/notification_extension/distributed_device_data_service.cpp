/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributed_device_data_service.h"

#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {

DistributedDeviceDataService& DistributedDeviceDataService::GetInstance()
{
    static DistributedDeviceDataService distributedDeviceDataService;
    return distributedDeviceDataService;
}

void DistributedDeviceDataService::ResetTargetDevice(const std::string& deviceType, const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto itemIter = devicesData_.begin(); itemIter != devicesData_.end(); itemIter++) {
        if (itemIter->deviceType == deviceType && itemIter->deviceId == deviceId) {
            devicesData_.erase(itemIter);
            ANS_LOGI("Reset device %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceId).c_str());
            return;
        }
    }
}

int32_t DistributedDeviceDataService::SetDeviceSyncSwitch(const std::string& deviceType, const std::string& deviceId,
    bool notificationEnable, bool liveViewEnable)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto itemIter = devicesData_.begin(); itemIter != devicesData_.end(); itemIter++) {
        if (itemIter->deviceType == deviceType && itemIter->deviceId == deviceId) {
            itemIter->liveViewSyncEnable = liveViewEnable;
            itemIter->notificationSyncEnable = notificationEnable;
            ANS_LOGI("Set device %{public}s %{public}d %{public}d", StringAnonymous(deviceId).c_str(),
                notificationEnable, liveViewEnable);
            return ERR_OK;
        }
    }

    if (deviceType.empty() || deviceId.empty()) {
        ANS_LOGW("Set device failed %{public}s %{public}d %{public}d", StringAnonymous(deviceId).c_str(),
            notificationEnable, liveViewEnable);
        return ERR_ANS_INVALID_PARAM;
    }
    DeviceData deviceData;
    deviceData.deviceType = deviceType;
    deviceData.deviceId = deviceId;
    deviceData.liveViewSyncEnable = liveViewEnable;
    deviceData.notificationSyncEnable = notificationEnable;
    devicesData_.emplace_back(deviceData);
    ANS_LOGI("Set device add %{public}s %{public}d %{public}d", StringAnonymous(deviceId).c_str(),
        notificationEnable, liveViewEnable);
    return ERR_OK;
}

int32_t DistributedDeviceDataService::SetTargetDeviceBundleList(const std::string& deviceType,
    const std::string& deviceId, int operatorType, const std::vector<std::string>& bundleList,
    const std::vector<std::string>& labelList)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto itemIter = devicesData_.begin(); itemIter != devicesData_.end(); itemIter++) {
        if (itemIter->deviceType != deviceType || itemIter->deviceId != deviceId) {
            continue;
        }
        ANS_LOGI("Set bundles %{public}s %{public}s %{public}d %{public}zu %{public}zu.",
            StringAnonymous(deviceId).c_str(), deviceType.c_str(), operatorType,
            itemIter->installedBundles.size(), bundleList.size());
        if (operatorType == BundleListOperationType::ADD_BUNDLES) {
            for (uint32_t i = 0; i < bundleList.size() && i < labelList.size(); i++) {
                itemIter->installedBundles[bundleList[i]] = labelList[i];
            }
        }

        if (operatorType == BundleListOperationType::REMOVE_BUNDLES) {
            for (uint32_t i = 0; i < bundleList.size() && i < labelList.size(); i++) {
                itemIter->installedBundles.erase(bundleList[i]);
            }
        }

        if (operatorType == BundleListOperationType::RELEASE_BUNDLES) {
            itemIter->installedBundles.clear();
        }
        ANS_LOGI("After Set bundles %{public}s %{public}d %{public}zu.",
            deviceType.c_str(), operatorType, itemIter->installedBundles.size());
        return ERR_OK;
    }

    if (deviceType.empty() || deviceId.empty() || operatorType != BundleListOperationType::ADD_BUNDLES) {
        ANS_LOGW("Set device failed %{public}s %{public}d", StringAnonymous(deviceId).c_str(),
            operatorType);
        return ERR_ANS_INVALID_PARAM;
    }

    DeviceData deviceData;
    deviceData.deviceType = deviceType;
    deviceData.deviceId = deviceId;
    for (uint32_t i = 0; i < bundleList.size() && i < labelList.size(); i++) {
        deviceData.installedBundles[bundleList[i]] = labelList[i];
    }
    devicesData_.emplace_back(deviceData);
    ANS_LOGI("Set device add %{public}s %{public}s %{public}zu", StringAnonymous(deviceId).c_str(),
        deviceType.c_str(), bundleList.size());
    return ERR_OK;
}

int32_t DistributedDeviceDataService::GetTargetDeviceBundleList(const std::string& deviceType,
    const std::string& deviceId, std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto& item : devicesData_) {
        if (item.deviceType == deviceType && item.deviceId == deviceId) {
            for (auto bundleInfo : item.installedBundles) {
                bundleList.push_back(bundleInfo.first);
                labelList.push_back(bundleInfo.second);
                return ERR_OK;
            }
        }
    }
    ANS_LOGW("Get bundle %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceId).c_str());
    return ERR_ANS_INVALID_PARAM;
}

bool DistributedDeviceDataService::CheckDeviceBundleExist(const std::string& deviceType, const std::string& deviceId,
    const std::string& bundleName, const std::string& label)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto& item : devicesData_) {
        if (item.deviceType != deviceType || item.deviceId != deviceId) {
            continue;
        }
        for (auto installedBundle : item.installedBundles) {
            if (installedBundle.first == bundleName || installedBundle.second == label) {
                return true;
            }
        }
    }
    ANS_LOGW("Get bundle failed %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceId).c_str());
    return false;
}

bool DistributedDeviceDataService::GetDeviceNotificationEnable(const std::string& deviceType,
    const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto& item : devicesData_) {
        if (item.deviceType == deviceType && item.deviceId == deviceId) {
            return item.notificationSyncEnable;
        }
    }
    ANS_LOGW("Get notification failed %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceId).c_str());
    return false;
}

bool DistributedDeviceDataService::GetDeviceLiveViewEnable(const std::string& deviceType, const std::string& deviceId)
{
    std::lock_guard<ffrt::mutex> lock(lock_);
    for (auto& item : devicesData_) {
        if (item.deviceType == deviceType && item.deviceId == deviceId) {
            return item.liveViewSyncEnable;
        }
    }
    ANS_LOGW("Get live view failed %{public}s %{public}s", deviceType.c_str(), StringAnonymous(deviceId).c_str());
    return false;
}
}
}
