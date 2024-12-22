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
#include "distributed_server.h"

#include "socket.h"
#include "session.h"
#include "distributed_device_data.h"
#include "dm_device_info.h"
#include "ans_log_wrapper.h"
#include "distributed_socket.h"

namespace OHOS {
namespace Notification {

using namespace DistributedHardware;

DistributedServer& DistributedServer::GetInstance()
{
    static DistributedServer distributedServer;
    return distributedServer;
}

void DistributedServer::ReleaseServer()
{
    ANS_LOGI("Release server socket %{public}u.", serverSocket_.size());
    for (auto& item : serverSocket_) {
        CloseSocket(item.second);
    }
}

int32_t DistributedServer::InitServer(const std::string &deviceId, uint16_t deviceType)
{
    localDevice_.deviceId_ = deviceId;
    localDevice_.deviceType_ = deviceType;
    int32_t socketId = ServiceListen(ANS_SOCKET_CMD, ANS_SOCKET_PKG, TransDataType::DATA_TYPE_MESSAGE);
    if (socketId == -1) {
        return -1;
    }

    std::string key = std::to_string(TransDataType::DATA_TYPE_MESSAGE) + "_" + std::to_string(deviceType);
    serverSocket_.insert(std::make_pair(key, socketId));
    // Not phone, create msg socket for receive notification
    if (deviceType != DmDeviceType::DEVICE_TYPE_PHONE) {
        socketId = ServiceListen(ANS_SOCKET_MSG, ANS_SOCKET_PKG, TransDataType::DATA_TYPE_BYTES);
        if (socketId == -1) {
            return -1;
        }
        std::string key = std::to_string(TransDataType::DATA_TYPE_BYTES) + "_" + std::to_string(deviceType);
        serverSocket_.insert(std::make_pair(key, socketId));
    }
    for (auto& item : serverSocket_) {
        ANS_LOGI("InitServer %{public}s %{public}s %{public}d", deviceId.c_str(),
            item.first.c_str(), item.second);
    }
    return 0;
}

void DistributedServer::OnBind(int32_t socket, PeerSocketInfo info)
{
    std::lock_guard<std::mutex> lock(serverLock_);
    std::shared_ptr<ConnectedSocketInfo> socketInfo = std::make_shared<ConnectedSocketInfo>();
    socketInfo->pkgName_ = info.pkgName;
    socketInfo->peerName_ = info.name;
    socketInfo->networkId_ = info.networkId;
    socketInfo->socketId_ = socket;
    socketInfo->dataType_ = info.dataType;
    peerSockets_.push_back(socketInfo);
}

void DistributedServer::OnShutdown(int32_t socket, ShutdownReason reason)
{
    std::lock_guard<std::mutex> lock(serverLock_);
    for (auto socketInfo = peerSockets_.begin(); socketInfo != peerSockets_.end();
        socketInfo++) {
        if ((*socketInfo)->socketId_ == socket) {
            peerSockets_.erase(socketInfo);
            break;
        }
    }
}

void DistributedServer::OnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    DistributedService::GetInstance().OnReceiveMsg(data, dataLen);
    ANS_LOGI("Distributed server On bytes %{public}u %{public}d", dataLen, socket);
}

void DistributedServer::OnMessage(int32_t socket, const void *data, uint32_t dataLen)
{
    DistributedService::GetInstance().OnReceiveMsg(data, dataLen);
    ANS_LOGI("Distributed server On message %{public}u %{public}d", dataLen, socket);
}
}
}
