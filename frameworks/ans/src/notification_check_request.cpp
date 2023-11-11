/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "notification_check_request.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {


NotificationCheckRequest::NotificationCheckRequest(NotificationContent::Type contentType,
    NotificationConstant::SlotType slotType, std::vector<std::string> extraKeys)
    : contentType_(contentType), slotType_(slotType), extraKeys_(extraKeys)
{}

NotificationCheckRequest::~NotificationCheckRequest()
{}

void NotificationCheckRequest::SetContentType(NotificationContent::Type contentType)
{
    contentType_ = contentType;
}

NotificationContent::Type NotificationCheckRequest::GetContentType() const
{
    return contentType_;
}

void NotificationCheckRequest::SetSlotType(NotificationConstant::SlotType slotType)
{
    slotType_ = slotType;
}

NotificationConstant::SlotType NotificationCheckRequest::GetSlotType() const
{
    return slotType_;
}

void NotificationCheckRequest::SetExtraKeys(std::vector<std::string> extraKeys)
{
    extraKeys_ = extraKeys;
}

std::vector<std::string> NotificationCheckRequest::GetExtraKeys() const
{
    return extraKeys_;
}

void NotificationCheckRequest::SetUid(const int32_t uid)
{
    creatorUid_ = uid;
}

int32_t NotificationCheckRequest::GetUid() const
{
    return creatorUid_;
}

bool NotificationCheckRequest::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(contentType_))) {
        ANS_LOGE("Failed to write content type");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(slotType_))) {
        ANS_LOGE("Failed to write slot type");
        return false;
    }
    if (!parcel.WriteStringVector(extraKeys_)) {
        ANS_LOGE("Failed to write extra info keys");
        return false;
    }

    return true;
}

NotificationCheckRequest *NotificationCheckRequest::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationCheckRequest();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }

    return objptr;
}

bool NotificationCheckRequest::ReadFromParcel(Parcel &parcel)
{
    contentType_ = static_cast<NotificationContent::Type>(parcel.ReadInt32());
    slotType_ = static_cast<NotificationConstant::SlotType>(parcel.ReadInt32());
    if (!parcel.ReadStringVector(&extraKeys_)) {
        ANS_LOGE("Failed to read extra info keys");
        return false;
    }
    return true;
}

}  // namespace Notification
}  // namespace OHOS
