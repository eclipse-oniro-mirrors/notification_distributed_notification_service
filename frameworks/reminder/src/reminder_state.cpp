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

#include "reminder_state.h"

namespace OHOS::Notification {
ReminderState::ReminderState(const ReminderState& other)
{
    reminderId_ = other.reminderId_;
    buttonType_ = other.buttonType_;
    isResend_ = other.isResend_;
}

ReminderState& ReminderState::operator=(const ReminderState& other)
{
    reminderId_ = other.reminderId_;
    buttonType_ = other.buttonType_;
    isResend_ = other.isResend_;
    return *this;
}

bool ReminderState::Marshalling(Parcel& parcel) const
{
    WRITE_INT32_RETURN_FALSE_LOG(parcel, reminderId_, "reminderId");
    int32_t buttonType = static_cast<int32_t>(buttonType_);
    WRITE_INT32_RETURN_FALSE_LOG(parcel, buttonType, "buttonType");
    WRITE_BOOL_RETURN_FALSE_LOG(parcel, isResend_, "isResend");
    return true;
}

bool ReminderState::ReadFromParcel(Parcel& parcel)
{
    READ_INT32_RETURN_FALSE_LOG(parcel, reminderId_, "reminderId");
    int32_t buttonType = static_cast<int32_t>(ReminderRequest::ActionButtonType::CLOSE);
    READ_INT32_RETURN_FALSE_LOG(parcel, buttonType, "buttonType");
    buttonType_ = static_cast<ReminderRequest::ActionButtonType>(buttonType);
    READ_BOOL_RETURN_FALSE_LOG(parcel, isResend_, "isResend");
    return true;
}

ReminderState* ReminderState::Unmarshalling(Parcel& parcel)
{
    auto obj = new (std::nothrow) ReminderState();
    if (obj == nullptr) {
        ANSR_LOGE("Failed to create reminder state due to no memory.");
        return nullptr;
    }
    if (!obj->ReadFromParcel(parcel)) {
        delete obj;
        obj = nullptr;
    }
    return obj;
}
}  // namespace OHOS::Notification