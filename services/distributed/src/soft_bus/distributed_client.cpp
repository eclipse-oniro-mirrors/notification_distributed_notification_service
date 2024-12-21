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
    for (auto& socketItem : socketsId_) {
        if (socketItem.second == socket) {
            socketItem.second = -1;
        }
    }
}

void DistributedClient::AddDevice(DistributedDeviceInfo peerDevice)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    ANS_LOGI("Distributed client AddDevice %{public}s", peerDevice.deviceId_.c_str());
    networksId_.insert(std::make_pair(peerDevice.deviceId_, peerDevice.networkId_));
}

void DistributedClient::ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    std::string messageKey = deviceId + '_' + std::to_string(TransDataType::DATA_TYPE_MESSAGE);
    std::string byteKey = deviceId + '_' + std::to_string(TransDataType::DATA_TYPE_BYTES);
    std::lock_guard<std::mutex> lock(clientLock_);
    auto socket = socketsId_.find(messageKey);
    if (socket != socketsId_.end()) {
        CloseSocket(socket->second);
        socketsId_.erase(socket);
    }
    socket = socketsId_.find(byteKey);
    if (socket != socketsId_.end()) {
        CloseSocket(socket->second);
        socketsId_.erase(socket);
    }
}

void DistributedClient::RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    ReleaseDevice(deviceId, deviceType);
    std::lock_guard<std::mutex> lock(clientLock_);
    auto networkIdItem = networksId_.find(deviceId);
    if (networkIdItem != networksId_.end()) {
        networkIdItem->second = networkId;
        return;
    }
    networksId_.insert(std::make_pair(deviceId, networkId));
}

int32_t DistributedClient::GetSocketId(const std::string &deviceId, uint16_t deviceType, TransDataType dataType)
{
    std::string key = deviceId + '_' + std::to_string(dataType);
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        auto socketItem = socketsId_.find(key);
        if (socketItem != socketsId_.end() && socketItem->second != -1) {
            return socketItem->second;
        }
    }

    std::string networkId;
    auto networkIdItem = networksId_.find(deviceId);
    if (networkIdItem != networksId_.end()) {
        networkId = networkIdItem->second;
    }
    std::string name = (dataType == TransDataType::DATA_TYPE_MESSAGE) ? ANS_SOCKET_CMD : ANS_SOCKET_MSG;
    int32_t socketId = ClientBind(name, ANS_SOCKET_PKG, name, networkId, dataType);
    if (socketId == -1) {
        ANS_LOGW("Get socketid failed %{public}s %{public}s %{public}d", deviceId.c_str(),
            networkId.c_str(), deviceType);
        return socketId;
    }
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        socketsId_.insert(std::make_pair(key, socketId));
    }
    return socketId;
}

int32_t DistributedClient::SendMessage(const void* data, int32_t length, TransDataType dataType,
    const std::string &deviceId, uint16_t deviceType)
{
    int32_t socketId = GetSocketId(deviceId, deviceType, dataType);
    if (socketId == -1) {
        ANS_LOGW("Get SocketId failed %{public}s %{public}d %{public}d", deviceId.c_str(), deviceType, dataType);
        return -1;
    }
    return ClientSendMsg(socketId, data, length, dataType);
}
}
}

