/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MATCH_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MATCH_BOX_H

#include <string>
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {
enum MatchType {
    MATCH_SYN = 0,
    MATCH_ACK,
    MATCH_OFFLINE,
};

class NotifticationMatchBox : public BoxBase {
public:
    NotifticationMatchBox();
    NotifticationMatchBox(std::shared_ptr<TlvBox> box);
    bool SetPeerDeviceType(const int32_t& deviceType);
    bool SetPeerDeviceId(const std::string& deviceId);
    bool SetLocalDeviceType(const int32_t& deviceType);
    bool SetLocalDeviceId(const std::string& deviceId);
    bool SetVersion(int32_t version);
    bool SetMatchType(int32_t type);
    bool SetDeviceUserId(const int32_t& userId);

    bool GetPeerDeviceType(int32_t& deviceType);
    bool GetPeerDeviceId(std::string& deviceId);
    bool GetLocalDeviceType(int32_t& deviceType);
    bool GetLocalDeviceId(std::string& deviceId);
    bool GetVersion(int32_t& version);
    bool GetMatchType(int32_t& type);
    bool GetDeviceUserId(int32_t& userId);
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_MATCH_BOX_H
