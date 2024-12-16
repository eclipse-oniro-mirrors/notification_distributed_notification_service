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

#include "state_box.h"

namespace OHOS {
namespace Notification {

NotifticationStateBox::NotifticationStateBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(NOTIFICATION_STATE_SYNC);
}

NotifticationStateBox::NotifticationStateBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotifticationStateBox::SetDeviceType(const std::string& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(DEVICE_TYPE, deviceType));
}

bool NotifticationStateBox::SetState(int32_t state)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(DEVICE_STATUS, state));
}

bool NotifticationStateBox::GetDeviceType(std::string& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(DEVICE_TYPE, deviceType);
}

bool NotifticationStateBox::GetState(int32_t& state)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(DEVICE_STATUS, state);
}
}
}