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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_CLIENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_CLIENT_H

#include <string>
#include <vector>
#include <thread>
#include "distributed_device_data.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {

class DistributedClient {
public:
    static DistributedClient& GetInstance();
    void OnShutdown(int32_t socket, ShutdownReason reason);
    void AddDevice(DistributedDeviceInfo peerDevice);
    void ReleaseDevice(const std::string &deviceId, uint16_t deviceType, bool releaseNetwork = true);
    void RefreshDevice(const std::string &deviceId, uint16_t deviceType,
        const std::string &networkId);
    void initClient(const std::string &deviceId, uint16_t deviceType);
    int32_t GetSocketId(const std::string &deviceId, TransDataType dataType, int32_t& socketId);
    int32_t SendMessage(const std::shared_ptr<BoxBase>& boxPtr, TransDataType dataType,
        const std::string &deviceId, int32_t eventType);
    void ReleaseClient();
private:
    DistributedClient() = default;
    ~DistributedClient() = default;

    std::string ShutdownReasonToString(ShutdownReason reason);
    std::mutex clientLock_;
    DistributedDeviceInfo localDevice_;
    std::map<std::string, int32_t> socketsId_;
    std::map<std::string, std::string> networksId_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_CLIENT_H
