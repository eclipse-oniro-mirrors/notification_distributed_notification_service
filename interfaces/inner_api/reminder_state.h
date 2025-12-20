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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_STATE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_STATE_H

#include <cstdint>

#include "reminder_request.h"

namespace OHOS::Notification {
class ReminderState : public Parcelable {
public:
    ReminderState() = default;
    ~ReminderState() = default;

    explicit ReminderState(const ReminderState& other);
    ReminderState& operator = (const ReminderState& other);

    bool Marshalling(Parcel& parcel) const override;
    bool ReadFromParcel(Parcel& parcel);
    static ReminderState* Unmarshalling(Parcel& parcel);

    int32_t reminderId_ {0};
    ReminderRequest::ActionButtonType buttonType_ {ReminderRequest::ActionButtonType::CLOSE};
    bool isResend_ {false};
};
}  // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_STATE_H
