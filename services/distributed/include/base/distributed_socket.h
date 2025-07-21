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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SOCKET_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SOCKET_H

#include <string>
#include "socket.h"
#include "distributed_service.h"

namespace OHOS {
namespace Notification {

int32_t ServiceListen(const std::string& name, const std::string& pkgName, TransDataType dataType,
    int32_t& socketId);

int32_t ClientBind(const std::string& name, const std::string& pkgName,
    const std::string& peerNetWorkId, TransDataType dataType, int32_t& socketId);

void CloseSocket(int32_t socketId);

int32_t ClientSendBytes(int32_t socketId, const void* data, uint32_t length);

int32_t ClientSendMessage(int32_t socketId, const void* data, uint32_t length);
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SOCKET_H
