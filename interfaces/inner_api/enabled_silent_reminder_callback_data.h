/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_ENABLED_SILENT_REMINDER_CALLBACK_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_ENABLED_SILENT_REMINDER_CALLBACK_DATA_H

#include "notification_constant.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class EnabledSilentReminderCallbackData : public Parcelable {
public:
    EnabledSilentReminderCallbackData() = default;
    EnabledSilentReminderCallbackData(
        std::string bundle, uid_t uid, NotificationConstant::SWITCH_STATE enableStatus);

    ~EnabledSilentReminderCallbackData() = default;

    void SetBundle(const std::string &bundle);

    std::string GetBundle() const;

    void SetUid(const uid_t uid);

    uid_t GetUid() const;

    void SetEnableStatus(const NotificationConstant::SWITCH_STATE enableStatus);
    NotificationConstant::SWITCH_STATE GetEnableStatus() const;

    std::string Dump();

    virtual bool Marshalling(Parcel &parcel) const override;

    static EnabledSilentReminderCallbackData *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

    std::string bundle_;
    uid_t uid_;
    NotificationConstant::SWITCH_STATE enableStatus_;
};
}  // namespace Notification
}  // namespace OHOS

#endif