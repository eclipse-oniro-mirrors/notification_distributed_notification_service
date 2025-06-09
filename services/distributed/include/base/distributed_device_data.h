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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_DEVICE_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_DEVICE_DATA_H

#include <string>
#include "socket.h"
#include "ans_log_wrapper.h"
#include "dm_device_info.h"
#include <unordered_set>

namespace OHOS {
namespace Notification {

constexpr char const ANS_SOCKET_CMD[] = "notification_service.cmd";
constexpr char const ANS_SOCKET_MSG[] = "notification_service.content";
constexpr char const ANS_SOCKET_PKG[] = "ohos.distributed_notification";
const int32_t CURRENT_VERSION = 1000;
const int32_t DEFAULT_ICON_WITHE = 60;
const int32_t DEFAULT_ICON_HEIGHT = 60;

enum DeviceState {
    STATE_INIT = 0,
    STATE_SYNC,
    STATE_ONLINE,
    STATE_OFFLINE,
    STATE_IDEL,
};

struct DistributedDeviceInfo {
    DistributedDeviceInfo() {}
    DistributedDeviceInfo(uint16_t deviceType, std::string deviceId)
        : deviceType_(deviceType), deviceId_(deviceId) {}
    DistributedDeviceInfo(uint16_t deviceType, std::string deviceId, std::string networkId)
        : deviceType_(deviceType), deviceId_(deviceId), networkId_(networkId) {}
    bool deviceUsage = false;
    bool liveViewSync = false;
    bool iconSync = false;
    bool installedBunlesSync = false;
    uint16_t deviceType_;
    int32_t peerState_ = DeviceState::STATE_INIT;
    int32_t socketId_ = -1;
    int32_t connectedTry_ = 0;
    std::string udid_;
    std::string deviceId_;
    std::string networkId_;
};

struct ConnectedSocketInfo {
    int32_t socketId_;
    std::string networkId_;
    std::string peerName_;
    std::string pkgName_;
    TransDataType dataType_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_DEVICE_DATA_H
