/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "remove_all_distributed_box.h"

namespace OHOS {
namespace Notification {

RemoveAllDistributedNotificationsBox::RemoveAllDistributedNotificationsBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(REMOVE_ALL_DISTRIBUTED_NOTIFICATIONS);
}

RemoveAllDistributedNotificationsBox::~RemoveAllDistributedNotificationsBox()
{}

RemoveAllDistributedNotificationsBox::RemoveAllDistributedNotificationsBox(
    std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool RemoveAllDistributedNotificationsBox::SetLocalDeviceId(const std::string &deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool RemoveAllDistributedNotificationsBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool RemoveAllDistributedNotificationsBox::SetSlotType(const int32_t slotTypeInt)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(REMOVE_SLOT_TYPE, slotTypeInt));
}

bool RemoveAllDistributedNotificationsBox::GetSlotType(int32_t &slotTypeInt) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(REMOVE_SLOT_TYPE, slotTypeInt);
}

bool RemoveAllDistributedNotificationsBox::SetOperationType(const int32_t operationType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(OPERATION_TYPE, operationType));
}

bool RemoveAllDistributedNotificationsBox::GetOperationType(int32_t &operationType) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(OPERATION_TYPE, operationType);
}

bool RemoveAllDistributedNotificationsBox::SetOperationReason(const int32_t operationReason)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(OPERATION_REASON, operationReason));
}

bool RemoveAllDistributedNotificationsBox::GetOperationReason(int32_t &operationReason) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(OPERATION_REASON, operationReason);
}
}
}