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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVER_H

#include <string>
#include <map>
#include <thread>
#include "distributed_device_data.h"

namespace OHOS {
namespace Notification {

class DistributedServer {
public:
    static DistributedServer& GetInstance();
    void CheckServer();
    void ReleaseServer();
    int32_t InitServer(const std::string &deviceId, uint16_t deviceType);
    void OnBind(int32_t socket, PeerSocketInfo info);
    void OnShutdown(int32_t socket, ShutdownReason reason);
    void OnBytes(int32_t socket, const void *data, uint32_t dataLen);
    void OnMessage(int32_t socket, const void *data, uint32_t dataLen);
private:
    DistributedServer() = default;
    ~DistributedServer() = default;
    std::atomic<bool> init = false;
    std::mutex serverLock_;
    DistributedDeviceInfo localDevice_;
    std::vector<std::shared_ptr<ConnectedSocketInfo>> peerSockets_;
    std::map<std::string, int32_t> serverSocket_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVER_H
