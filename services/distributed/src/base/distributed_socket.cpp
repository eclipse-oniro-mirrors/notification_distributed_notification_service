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
#include "distributed_socket.h"

#include <thread>
#include "socket.h"
#include "session.h"
#include "distributed_server.h"
#include "distributed_client.h"
#include "distributed_const_define.h"

namespace OHOS {
namespace Notification {

static const int32_t BIND_SERVICE_MAX_RETRY_TIMES = 1;
static const int32_t BIND_SERVICE_SLEEP_TIMES_MS = 10000;  // 10s
static const uint32_t SOCKET_NAME_MAX_LEN = 256;
static const int32_t QOS_NUM = 5;

static void OnServerBind(int32_t socket, PeerSocketInfo info)
{
    ANS_LOGI("Socket fd is %{public}d.", socket);
    if (socket <= 0) {
        ANS_LOGE("Socket fd invalid.");
        return;
    }
    DistributedServer::GetInstance().OnBind(socket, info);
}

static void OnServerShutdown(int32_t socket, ShutdownReason reason)
{
    ANS_LOGI("Socket fd %{public}d shutdown because %{public}zu.", socket, reason);
    if (socket <= 0) {
        ANS_LOGE("Socket fd invalid.");
        return;
    }
    DistributedServer::GetInstance().OnShutdown(socket, reason);
}

static void OnServerBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    ANS_LOGI("Socket byte fd %{public}d, recv len %{public}d.", socket, dataLen);
    if ((socket <= 0) || (data == nullptr) || (dataLen == 0)) {
        ANS_LOGW("Socket byte invalid data.");
        return;
    }
    DistributedServer::GetInstance().OnBytes(socket, data, dataLen);
}

static void OnServerMessage(int32_t socket, const void *data, uint32_t dataLen)
{
    ANS_LOGI("Socket byte fd %{public}d, recv len %{public}d.", socket, dataLen);
    if ((socket <= 0) || (data == nullptr) || (dataLen == 0)) {
        ANS_LOGW("Socket byte invalid data.");
        return;
    }
    DistributedServer::GetInstance().OnMessage(socket, data, dataLen);
}

static void OnClientBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    ANS_LOGI("Socket message fd %{public}d, recv len %{public}d.", socket, dataLen);
    if ((socket <= 0) || (data == nullptr) || (dataLen == 0)) {
        ANS_LOGW("Socket message invalid data.");
    }
    DistributedServer::GetInstance().OnMessage(socket, data, dataLen);
}

static void OnClientShutdown(int32_t socket, ShutdownReason reason)
{
    ANS_LOGI("Socket fd %{public}d shutdown because %{public}zu.", socket, reason);
    if (socket <= 0) {
        ANS_LOGE("Socket fd invalid.");
        return;
    }
    DistributedClient::GetInstance().OnShutdown(socket, reason);
}

static void OnQos(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    ANS_LOGI("OnQos %{public}d %{public}d %{public}zu", socket, (int32_t)eventId, qosCount);
}

void CloseSocket(int32_t socketId)
{
    ANS_LOGI("Close socket id %{public}d", socketId);
    ::Shutdown(socketId);
}

bool CheckAndCopyStr(char* dest, uint32_t destLen, const std::string& src)
{
    if (destLen < src.length() + 1) {
        return false;
    }
    if (strcpy_s(dest, destLen, src.c_str()) != EOK) {
        return false;
    }
    return true;
}

int32_t ServiceListen(const std::string& name, const std::string& pkgName, TransDataType dataType, int32_t& socketId)
{
    char nameStr[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(nameStr, SOCKET_NAME_MAX_LEN, name)) {
        return DISRTIBUED_ERR;
    }

    char pkgNameStr[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgNameStr, SOCKET_NAME_MAX_LEN, pkgName)) {
        return DISRTIBUED_ERR;
    }

    SocketInfo info = { .name = nameStr, .pkgName = pkgNameStr, .dataType = dataType };
    socketId = ::Socket(info); // create service socket id
    if (socketId <= 0) {
        ANS_LOGW("Create socket faild, %{public}s %{public}s %{public}d.", nameStr, pkgNameStr, socketId);
        return DISRTIBUED_SOCKET_CREATE_ERR;
    }

    QosTV serverQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = 64*1024 },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 10000 },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000 },
    };
    ISocketListener listener;
    listener.OnBind = OnServerBind; // only service may receive OnBind
    listener.OnQos = OnQos; // only service may receive OnBind
    listener.OnShutdown = OnServerShutdown;
    listener.OnBytes = OnServerBytes;
    listener.OnMessage = OnServerMessage;
    int32_t ret = ::Listen(socketId, serverQos, 3, &listener);
    if (ret != ERR_OK) {
        ::Shutdown(socketId);
        ANS_LOGW("Create listener failed, ret is %{public}d.", ret);
        return ret;
    }
    ANS_LOGI("Service listen %{public}s %{public}d %{public}d.", name.c_str(), dataType, socketId);
    return ERR_OK;
}

int32_t ClientBind(const std::string& name, const std::string& pkgName,
    const std::string& peerNetWorkId, TransDataType dataType, int32_t& socketId)
{
    char nameStr[SOCKET_NAME_MAX_LEN + 1];
    char peerNetWorkIdStr[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(nameStr, SOCKET_NAME_MAX_LEN, name) ||
        !CheckAndCopyStr(peerNetWorkIdStr, SOCKET_NAME_MAX_LEN, peerNetWorkId)) {
        return DISRTIBUED_ERR;
    }
    char pkgNameStr[SOCKET_NAME_MAX_LEN + 1];
    char peerNameStr[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgNameStr, SOCKET_NAME_MAX_LEN, pkgName) ||
        !CheckAndCopyStr(peerNameStr, SOCKET_NAME_MAX_LEN, name)) {
        return DISRTIBUED_ERR;
    }
    SocketInfo info = { .name = nameStr, .peerName = peerNameStr, .peerNetworkId = peerNetWorkIdStr,
        .pkgName = pkgNameStr, .dataType = dataType };
    socketId = ::Socket(info); // create client socket id
    if (socketId <= 0) {
        ANS_LOGW("Create client socket faild, ret is %{public}d.", socketId);
        return DISRTIBUED_SOCKET_CREATE_ERR;
    }

    QosTV clientQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = 64*1024 }, { .qos = QOS_TYPE_MAX_LATENCY, .value = 10000 },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000 }, { .qos = QOS_TYPE_TRANS_CONTINUOUS, .value = 1 },
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = 600000 },
    };
    ISocketListener listener;
    listener.OnQos = OnQos;
    listener.OnShutdown = OnClientShutdown;
    listener.OnBytes = OnClientBytes;

    // retry 10 times or bind success
    int32_t result = 0;
    int32_t retryTimes = 0;
    auto sleepTime = std::chrono::milliseconds(BIND_SERVICE_SLEEP_TIMES_MS);
    bool bindSuccess = false;
    while (retryTimes < BIND_SERVICE_MAX_RETRY_TIMES) {
        result = ::Bind(socketId, clientQos, QOS_NUM, &listener);
        if (result != 0) {
            ANS_LOGE("Bind Server failed, ret is %{public}d.", result);
            retryTimes++;
            continue;
        }
        bindSuccess = true;
        break;
    }

    if (!bindSuccess) {
        ::Shutdown(socketId); // close client.
        return result;
    }
    return ERR_OK;
}

int32_t ClientSendBytes(int32_t socketId, const void* data, uint32_t length)
{
    if (data == nullptr || length <= 0) {
        ANS_LOGE("Invalid Parameters.");
        return DISRTIBUED_ERR;
    }
    int32_t result = ::SendBytes(socketId, data, length);
    ANS_LOGI("Socket send byte %{public}d %{public}d %{public}d ", socketId, length, result);
    return result;
}

int32_t ClientSendMessage(int32_t socketId, const void* data, uint32_t length)
{
    if (data == nullptr || length <= 0) {
        ANS_LOGE("Invalid Parameters.");
        return DISRTIBUED_ERR;
    }
    int32_t result = ::SendMessage(socketId, data, length);
    ANS_LOGI("Socket send message %{public}d %{public}d %{public}d ", socketId, length, result);
    return result;
}

}
}
