/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ADAPTATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ADAPTATION_H

#include "reminder_request.h"

namespace OHOS {
namespace Notification {
class ReminderRequestAdaptation : public Parcelable {
public:
    virtual bool Marshalling(Parcel &parcel) const override;
    static ReminderRequestAdaptation *Unmarshalling(Parcel &parcel);
    sptr<ReminderRequest> reminderRequest_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ADAPTATION_H