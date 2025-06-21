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

#include "batch_remove_box.h"

namespace OHOS {
namespace Notification {

BatchRemoveNotificationBox::BatchRemoveNotificationBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(REMOVE_ALL_NOTIFICATIONS);
}

BatchRemoveNotificationBox::~BatchRemoveNotificationBox()
{}

BatchRemoveNotificationBox::BatchRemoveNotificationBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{}

bool BatchRemoveNotificationBox::SetNotificationHashCodes(const std::string& hashCodes)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hashCodes));
}

bool BatchRemoveNotificationBox::SetNotificationSlotTypes(const std::string &slotTypes)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BATCH_REMOVE_SLOT_TYPE, slotTypes));
}

bool BatchRemoveNotificationBox::SetLocalDeviceId(const std::string &deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool BatchRemoveNotificationBox::GetNotificationHashCodes(std::string& hashCodes) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hashCodes);
}

bool BatchRemoveNotificationBox::GetNotificationSlotTypes(std::string& slotTypes) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(BATCH_REMOVE_SLOT_TYPE, slotTypes);
}

bool BatchRemoveNotificationBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}
}
}
