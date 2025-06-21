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

#include "remove_box.h"

namespace OHOS {
namespace Notification {

NotificationRemoveBox::NotificationRemoveBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(REMOVE_NOTIFICATION);
}

NotificationRemoveBox::~NotificationRemoveBox()
{}

NotificationRemoveBox::NotificationRemoveBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotificationRemoveBox::SetNotificationHashCode(const std::string& hashCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hashCode));
}

bool NotificationRemoveBox::SetNotificationSlotType(int32_t slotType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_SLOT_TYPE, slotType));
}


bool NotificationRemoveBox::SetLocalDeviceId(const std::string &deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool NotificationRemoveBox::GetNotificationHashCode(std::string& hashCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hashCode);
}

bool NotificationRemoveBox::GetNotificationSlotType(int32_t &slotType) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_SLOT_TYPE, slotType);
}

bool NotificationRemoveBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}
}
}