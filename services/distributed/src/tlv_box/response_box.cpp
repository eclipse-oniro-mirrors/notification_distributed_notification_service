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

#include "response_box.h"

namespace OHOS {
namespace Notification {

NotificationResponseBox::NotificationResponseBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(NOTIFICATION_RESPONSE_SYNC);
}

NotificationResponseBox::NotificationResponseBox(std::shared_ptr<TlvBox> box) : BoxBase(box) {}

bool NotificationResponseBox::SetMessageType(int32_t messageType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->SetMessageType(messageType);
}

bool NotificationResponseBox::SetNotificationHashCode(const std::string& hashCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hashCode));
}

bool NotificationResponseBox::SetOperationEventId(const std::string& eventId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(OPERATION_EVENT_ID, eventId));
}

bool NotificationResponseBox::SetActionName(const std::string& actionName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_BUTTON_NAME, actionName));
}

bool NotificationResponseBox::SetUserInput(const std::string& userInput)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_USER_INPUT, userInput));
}

bool NotificationResponseBox::SetOperationType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(OPERATION_TYPE, type));
}

bool NotificationResponseBox::SetMatchType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(MATCH_TYPE, type));
}

bool NotificationResponseBox::SetLocalDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool NotificationResponseBox::SetResponseResult(int32_t result)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(RESULT_CODE, result));
}

bool NotificationResponseBox::GetNotificationHashCode(std::string& hashCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hashCode);
}

bool NotificationResponseBox::GetOperationEventId(std::string& eventId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(OPERATION_EVENT_ID, eventId);
}

bool NotificationResponseBox::GetActionName(std::string& actionName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_BUTTON_NAME, actionName);
}

bool NotificationResponseBox::GetUserInput(std::string& userInput) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_USER_INPUT, userInput);
}

bool NotificationResponseBox::GetOperationType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(OPERATION_TYPE, type);
}

bool NotificationResponseBox::GetMatchType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(MATCH_TYPE, type);
}

bool NotificationResponseBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool NotificationResponseBox::GetResponseResult(int32_t& result) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(RESULT_CODE, result);
}
} // namespace Notification
} // namespace OHOS
