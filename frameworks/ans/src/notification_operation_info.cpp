/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "notification_operation_info.h"

#include "ans_log_wrapper.h"
#include "message_user.h"                         // for MessageUser
#include "nlohmann/json.hpp"                      // for json, basic_json<>:...
#include "notification_json_convert.h"            // for NotificationJsonCon...
#include "parcel.h"                               // for Parcel
#include "uri.h"                                  // for Uri

namespace OHOS {
namespace Notification {

std::string NotificationOperationInfo::GetActionName() const
{
    return actionName_;
}

void NotificationOperationInfo::SetActionName(const std::string& actionName)
{
    actionName_ = actionName;
}

std::string NotificationOperationInfo::GetUserInput() const
{
    return userInput_;
}

void NotificationOperationInfo::SetUserInput(const std::string& userInput)
{
    userInput_ = userInput;
}

std::string NotificationOperationInfo::GetHashCode() const
{
    return hashCode_;
}

void NotificationOperationInfo::SetHashCode(const std::string& hashCode)
{
    hashCode_ = hashCode;
}

std::string NotificationOperationInfo::GetEventId() const
{
    return eventId_;
}

void NotificationOperationInfo::SetEventId(const std::string& eventId)
{
    eventId_ = eventId;
}

OperationType NotificationOperationInfo::GetOperationType() const
{
    return operationType_;
}

void NotificationOperationInfo::SetOperationType(const OperationType& operationType)
{
    operationType_ = operationType;
}

std::string NotificationOperationInfo::Dump()
{
    return "NotificationOperationInfo{ "
        "hashCode = " + hashCode_ +
        ", eventId = " + eventId_ +
        ", actionName = " + actionName_ +
        ", operationType = " + std::to_string(static_cast<int32_t>(operationType_)) +
        " }";
}

bool NotificationOperationInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(actionName_)) {
        ANS_LOGE("Failed to write action name");
        return false;
    }

    if (!parcel.WriteString(userInput_)) {
        ANS_LOGE("Failed to write user input");
        return false;
    }

    if (!parcel.WriteString(hashCode_)) {
        ANS_LOGE("Failed to write user input");
        return false;
    }

    if (!parcel.WriteString(eventId_)) {
        ANS_LOGE("Failed to write user input");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(operationType_))) {
        ANS_LOGE("Failed to write user input");
        return false;
    }

    return true;
}

bool NotificationOperationInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(actionName_)) {
        ANS_LOGE("Failed to read action name");
        return false;
    }

    if (!parcel.ReadString(userInput_)) {
        ANS_LOGE("Failed to read user input");
        return false;
    }

    if (!parcel.ReadString(hashCode_)) {
        ANS_LOGE("Failed to read action name");
        return false;
    }

    if (!parcel.ReadString(eventId_)) {
        ANS_LOGE("Failed to read user input");
        return false;
    }

    operationType_ = static_cast<OperationType>(parcel.ReadInt32());

    return true;
}

NotificationOperationInfo *NotificationOperationInfo::Unmarshalling(Parcel &parcel)
{
    auto operationInfo = new (std::nothrow) NotificationOperationInfo();
    if (operationInfo && !operationInfo->ReadFromParcel(parcel)) {
        delete operationInfo;
        operationInfo = nullptr;
    }

    return operationInfo;
}

}  // namespace Notification
}  // namespace OHOS
