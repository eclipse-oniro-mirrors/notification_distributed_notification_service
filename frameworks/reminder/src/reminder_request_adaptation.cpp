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

#include "reminder_request.h"
#include "reminder_request_factory.h"
#include "reminder_request_adaptation.h"

namespace OHOS {
namespace Notification {
bool ReminderRequestAdaptation::Marshalling(Parcel &parcel) const
{
    return reminderRequest_->Marshalling(parcel);
}

ReminderRequestAdaptation* ReminderRequestAdaptation::Unmarshalling(Parcel &parcel)
{
    ReminderRequest::ReminderType tarReminderType = ReminderRequest::ReminderType::INVALID;
    ReminderRequest::ReadReminderTypeFormParcel(parcel, tarReminderType);
    auto reminderRequest = ReminderRequestFactory::CreateReminderRequest(tarReminderType);
    if (reminderRequest == nullptr) {
        ANSR_LOGE("null reminderRequest");
        return nullptr;
    }
    if (!reminderRequest->ReadFromParcel(parcel)) {
        delete reminderRequest;
        return nullptr;
    }
    ReminderRequestAdaptation* reminderRequestAdaptation = new (std::nothrow) ReminderRequestAdaptation();
    if (reminderRequestAdaptation == nullptr) {
        delete reminderRequest;
        return nullptr;
    }
    reminderRequestAdaptation->reminderRequest_ = reminderRequest;
    return reminderRequestAdaptation;
}

}  // namespace Notification
}  // namespace OHOS
