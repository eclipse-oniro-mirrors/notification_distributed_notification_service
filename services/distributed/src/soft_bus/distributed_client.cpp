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
#include "distributed_client.h"

#include "socket.h"
#include "session.h"
#include "distributed_socket.h"

namespace OHOS {
namespace Notification {

DistributedClient& DistributedClient::GetInstance()
{
    static DistributedClient distributedClient;
    return distributedClient;
}

void DistributedClient::OnShutdown(int32_t socket, ShutdownReason reason)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    for (auto& device : peerDevices_) {
        if (socket == device.socketId_) {
            device.socketId_ = -1;
        }
    }
}

void DistributedClient::AddDevice(DistributedDeviceInfo peerDevice)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    peerDevices_.push_back(peerDevice);
}

void DistributedClient::ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    for (auto device = peerDevices_.begin(); device != peerDevices_.end(); device++) {
        if (device->deviceId_ == deviceId && device->deviceType_ == deviceType) {
            CloseSocket(device->socketId_);
            peerDevices_.erase(device);
            break;
        }
    }
}

void DistributedClient::RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    for (auto& device : peerDevices_) {
        if (device.deviceId_ == deviceId && device.deviceType_ == deviceType &&
            device.networkId_ != networkId) {
            CloseSocket(device.socketId_);
            device.socketId_ = -1;
            device.networkId_ = networkId;
        }
    }
}

int32_t DistributedClient::GetSocketId(const std::string &deviceId, uint16_t deviceType, TransDataType dataType)
{
    int32_t socketId = -1;
    std::string networkId;
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        for (const auto& device : peerDevices_) {
            if (device.deviceId_ == deviceId && device.deviceType_ == deviceType) {
                socketId = device.socketId_;
                networkId = device.networkId_;
                break;
            }
        }
    }
    if (socketId != -1) {
        return socketId;
    }

    std::string name = (dataType == TransDataType::DATA_TYPE_MESSAGE) ? ANS_SOCKET_CMD : ANS_SOCKET_MSG;
    socketId = ClientBind(name, ANS_SOCKET_PKG, name, networkId, dataType);
    if (socketId == -1) {
        ANS_LOGW("Get socketid failed %{public}s %{public}d", deviceId.c_str(), deviceType);
        return socketId;
    }
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        for (auto& device : peerDevices_) {
            if (device.deviceId_ == deviceId && device.deviceType_ == deviceType) {
                device.socketId_ = socketId;
                break;
            }
        }
    }
    return socketId;
}

void DistributedClient::SendMessage(const void* data, int32_t length, TransDataType dataType,
    const std::string &deviceId, uint16_t deviceType)
{
    int32_t socketId = GetSocketId(deviceId, deviceType, dataType);
    if (socketId == -1) {
        ANS_LOGW("Get SocketId failed %{public}s %{public}d %{public}d", deviceId.c_str(), deviceType, dataType);
        return;
    }
    ClientSendMsg(socketId, data, length, dataType);
}
}
}
