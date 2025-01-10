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

bool BatchRemoveNotificationBox::SetNotificationHashCode(const std::string& hashCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hashCode));
}
}
}
