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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MANAGER_H

#include "distributed_device_data.h"

namespace OHOS {
namespace Notification {
class DistributedManager {
public:
    DistributedManager();
    ~DistributedManager() = default;
    static DistributedManager& GetInstance();
    void ReleaseLocalDevice();
    int32_t InitLocalDevice(const std::string &deviceId, uint16_t deviceType,
        int32_t titleLength, int32_t contentLength,
        std::function<bool(std::string, int32_t, bool)> callback);
    void AddDevice(const std::string &deviceId, uint16_t deviceType,
        const std::string &networkId);
    void ReleaseDevice(const std::string &deviceId, uint16_t deviceType);
    void RefreshDevice(const std::string &deviceId, uint16_t deviceType,
        const std::string &networkId);
};
}
}

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MANAGER_H
