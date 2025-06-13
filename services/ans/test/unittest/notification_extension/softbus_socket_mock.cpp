/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "socket.h"


int32_t Socket(SocketInfo info)
{
    return 1;
}

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    return 0;
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    return 0;
}

int32_t BindAsync(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    return 0;
}

int32_t SendBytes(int32_t socket, const void *data, uint32_t len)
{
    return 0;
}

int32_t SendBytesAsync(int32_t socket, uint32_t dataSeq, const void *data, uint32_t len)
{
    return 0;
}

int32_t SendMessage(int32_t socket, const void *data, uint32_t len)
{
    return 0;
}

int32_t SendStream(int32_t socket, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    return 0;
}

int32_t SendFile(int32_t socket, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    return 0;
}

void Shutdown(int32_t socket)
{
}

int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    return 0;
}

int32_t SetAccessInfo(int32_t socket, SocketAccessInfo accessInfo)
{
    return 0;
}
