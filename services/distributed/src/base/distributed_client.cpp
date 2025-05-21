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
#include "distributed_server.h"
#include "analytics_util.h"

namespace OHOS {
namespace Notification {

DistributedClient& DistributedClient::GetInstance()
{
    static DistributedClient distributedClient;
    return distributedClient;
}

void DistributedClient::ReleaseClient()
{
    std::lock_guard<std::mutex> lock(clientLock_);
    ANS_LOGI("Release client socket %{public}d.", (int32_t)(socketsId_.size()));
    for (auto& socketItem : socketsId_) {
        CloseSocket(socketItem.second);
    }
    socketsId_.clear();
}

void DistributedClient::OnShutdown(int32_t socket, ShutdownReason reason)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    for (auto& socketItem : socketsId_) {
        if (socketItem.second == socket) {
            socketItem.second = -1;
            std::string message = "socketID: " + std::to_string(socket) + " ; ShutdownReason: " +
                                  ShutdownReasonToString(reason);
            AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, 0,
                BRANCH4_ID, message, PUBLISH_ERROR_EVENT_CODE);
        }
    }
}

void DistributedClient::AddDevice(DistributedDeviceInfo peerDevice)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    ANS_LOGI("Distributed client AddDevice %{public}s %{public}s", StringAnonymous(peerDevice.deviceId_).c_str(),
        StringAnonymous(peerDevice.networkId_).c_str());
    networksId_[peerDevice.deviceId_] = peerDevice.networkId_;
    std::string message = "AddnetworkId: " + StringAnonymous(peerDevice.deviceId_) + " id: " +
        StringAnonymous(peerDevice.networkId_);
    AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, 0,
        BRANCH6_ID, message, PUBLISH_ERROR_EVENT_CODE);
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
    networksId_.erase(deviceId);
    std::string message = "ReleasenetworkId: " + StringAnonymous(deviceId);
    AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, 0,
        BRANCH7_ID, message, PUBLISH_ERROR_EVENT_CODE);
}

void DistributedClient::RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    ReleaseDevice(deviceId, deviceType);
    std::lock_guard<std::mutex> lock(clientLock_);
    networksId_[deviceId] = networkId;
    ANS_LOGI("Distributed refresh device %{public}s %{public}s", StringAnonymous(deviceId).c_str(),
        StringAnonymous(networkId).c_str());
    std::string message = "RefreshnetworkId: " + StringAnonymous(deviceId) + " id: " +
        StringAnonymous(networkId);
    AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, 0,
        BRANCH8_ID, message, PUBLISH_ERROR_EVENT_CODE);
}

int32_t DistributedClient::GetSocketId(const std::string &deviceId, TransDataType dataType, int32_t& socketId)
{
    std::string key = deviceId + '_' + std::to_string(dataType);
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        auto socketItem = socketsId_.find(key);
        if (socketItem != socketsId_.end() && socketItem->second != -1) {
            socketId = socketItem->second;
            return ERR_OK;
        }
    }

    std::string networkId;
    auto networkIdItem = networksId_.find(deviceId);
    if (networkIdItem != networksId_.end()) {
        networkId = networkIdItem->second;
    }
    std::string name = (dataType == TransDataType::DATA_TYPE_MESSAGE) ? ANS_SOCKET_CMD : ANS_SOCKET_MSG;
    int32_t result = ClientBind(name, ANS_SOCKET_PKG, networkId, dataType, socketId);
    if (result != ERR_OK) {
        ANS_LOGW("Get socketid failed %{public}s %{public}s %{public}d", StringAnonymous(deviceId).c_str(),
            StringAnonymous(networkId).c_str(), dataType);
        std::string message = "Get socketid failed: " + StringAnonymous(deviceId) + " id: " +
            StringAnonymous(networkId);
        AnalyticsUtil::GetInstance().SendHaReport(OPERATION_DELETE_BRANCH, result,
            BRANCH8_ID, message, PUBLISH_ERROR_EVENT_CODE);
        return result;
    }
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        socketsId_[key] = socketId;
        ANS_LOGI("Get socketid insert %{public}s %{public}d", key.c_str(), socketId);
    }
    return ERR_OK;
}

int32_t DistributedClient::SendMessage(const std::shared_ptr<BoxBase>& boxPtr, TransDataType dataType,
    const std::string &deviceId, int32_t eventType)
{
    int32_t type = -1;
    int32_t socketId = 0;
    DistributedServer::GetInstance().CheckServer();
    int32_t result = GetSocketId(deviceId, dataType, socketId);
    if (boxPtr == nullptr || boxPtr->box_ == nullptr) {
        ANS_LOGW("Dans send message failed %{public}s", StringAnonymous(deviceId).c_str());
        return -1;
    }
    boxPtr->box_->GetMessageType(type);
    if (result != ERR_OK) {
        ANS_LOGW("Get SocketId failed %{public}s %{public}d", StringAnonymous(deviceId).c_str(), dataType);
        std::string errorReason = "Bind failed type: " + std::to_string(type) + " , id: " + StringAnonymous(deviceId);
        AnalyticsUtil::GetInstance().SendEventReport(0, result, errorReason);
        AnalyticsUtil::GetInstance().SendHaReport(eventType, result, BRANCH1_ID, errorReason);
        return result;
    }
    result = ClientSendMsg(socketId, boxPtr->GetByteBuffer(), boxPtr->GetByteLength(), dataType);
    if (result != ERR_OK) {
        std::string errorReason = "Send failed type: " + std::to_string(type) + " , id: " + StringAnonymous(deviceId);
        AnalyticsUtil::GetInstance().SendEventReport(0, result, errorReason);
        AnalyticsUtil::GetInstance().SendHaReport(eventType, result, BRANCH2_ID, errorReason);
    }
    return result;
}

std::string DistributedClient::ShutdownReasonToString(ShutdownReason reason)
{
    switch (reason) {
        case ShutdownReason::SHUTDOWN_REASON_UNKNOWN:
            return "SHUTDOWN_REASON_UNKNOWN";
        case ShutdownReason::SHUTDOWN_REASON_PEER:
            return "SHUTDOWN_REASON_PEER";
        case ShutdownReason::SHUTDOWN_REASON_LNN_CHANGED:
            return "SHUTDOWN_REASON_LNN_CHANGED";
        case ShutdownReason::SHUTDOWN_REASON_CONN_CHANGED:
            return "SHUTDOWN_REASON_CONN_CHANGED";
        case ShutdownReason::SHUTDOWN_REASON_TIMEOUT:
            return "SHUTDOWN_REASON_TIMEOUT";
        case ShutdownReason::SHUTDOWN_REASON_SEND_FILE_ERR:
            return "SHUTDOWN_REASON_SEND_FILE_ERR";
        case ShutdownReason::SHUTDOWN_REASON_RECV_FILE_ERR:
            return "SHUTDOWN_REASON_RECV_FILE_ERR";
        case ShutdownReason::SHUTDOWN_REASON_RECV_DATA_ERR:
            return "SHUTDOWN_REASON_RECV_DATA_ERR";
        case ShutdownReason::SHUTDOWN_REASON_UNEXPECTED:
            return "SHUTDOWN_REASON_UNEXPECTED";
        default:
            return "unknown";
    }
}

}
}

