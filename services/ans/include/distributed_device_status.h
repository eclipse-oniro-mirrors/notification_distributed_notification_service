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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H

#include <cstdint>
#include <singleton.h>
#include <string>
#include <vector>

#include "errors.h"
#include "ans_log_wrapper.h"
#include "safe_map.h"

namespace OHOS {
namespace Notification {

struct DeviceStatus {
    DeviceStatus(std::string type, std::string id) : deviceType(type), deviceId(id) {}
    std::string deviceType;
    std::string deviceId;
    uint32_t status = 0;
    int32_t userId = 0;
};

class DistributedDeviceStatus : public DelayedSingleton<DistributedDeviceStatus> {
public:
    DistributedDeviceStatus();
    ~DistributedDeviceStatus();
    ErrCode SetDeviceStatus(const std::string &deviceType, const uint32_t status,
        const uint32_t controlFlag);
    ErrCode SetDeviceStatus(const std::string &deviceType, const uint32_t status,
        const uint32_t controlFlag, const std::string deviceId, int32_t userId);

    uint32_t GetDeviceStatus(const std::string &deviceType);

    DeviceStatus GetMultiDeviceStatus(const std::string &deviceType, const uint32_t status);

private:
    std::mutex mapLock_;
    std::vector<DeviceStatus> deviceInfo_;
    SafeMap<std::string, uint32_t> deviceStatus_;

public:
    static constexpr int32_t NETWORKID_FLAG = 16;
    static constexpr int32_t USERID_FLAG = 4;
    static constexpr int32_t STATUS_SIZE = 4;
    static constexpr int32_t USING_FLAG = 0;
    static constexpr int32_t LOCK_FLAG = 1;
    static constexpr int32_t OWNER_FLAG = 2;
    static constexpr int32_t DISTURB_MODE_FLAG = 3;
    static constexpr int32_t DISTURB_DEFAULT_FLAG = 13;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H
