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
    std::lock_guard<std::mutex> lock(mapLock_);
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

uint32_t DistributedDeviceStatus::GetDeviceStatus(const std::string &deviceType)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    return deviceStatus_.ReadVal(deviceType);
}
} // namespace Notification
} // namespace OHOS
