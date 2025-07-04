/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_RESPONSE_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_RESPONSE_BOX_H

#include <string>

#include "box_base.h"
#include "tlv_box.h"

namespace OHOS {
namespace Notification {
class NotificationResponseBox : public BoxBase {
public:
    NotificationResponseBox();
    NotificationResponseBox(std::shared_ptr<TlvBox> box);
    bool SetMessageType(int32_t messageType);
    bool SetNotificationHashCode(const std::string& hashCode);
    bool SetOperationEventId(const std::string& eventId);
    bool SetActionName(const std::string& actionName);
    bool SetUserInput(const std::string& userInput);
    bool SetOperationType(int32_t type);
    bool SetOperationBtnIndex(const int32_t index);
    bool SetOperationJumpType(const int32_t jumpType);
    bool SetMatchType(int32_t type);
    bool SetLocalDeviceId(const std::string& deviceId);
    bool SetResponseResult(int32_t result);

    bool GetNotificationHashCode(std::string& hashCode) const;
    bool GetOperationEventId(std::string& eventId) const;
    bool GetActionName(std::string& actionName) const;
    bool GetUserInput(std::string& userInput) const;
    bool GetOperationType(int32_t& type) const;
    bool GetOperationBtnIndex(int32_t& index) const;
    bool GetOperationJumpType(int32_t& jumpType) const;
    bool GetMatchType(int32_t& type) const;
    bool GetLocalDeviceId(std::string& deviceId) const;
    bool GetResponseResult(int32_t& result) const;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H
