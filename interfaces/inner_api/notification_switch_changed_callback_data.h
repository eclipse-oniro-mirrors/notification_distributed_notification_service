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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_NOTIFICATION_SWITCH_CHANGED_CALLBACK_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_NOTIFICATION_SWITCH_CHANGED_CALLBACK_DATA_H

#include <string>

#include "ans_const_define.h"
#include "notification_constant.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationSwitchChangedCallbackData : public Parcelable {
public:
    NotificationSwitchChangedCallbackData() = default;
    NotificationSwitchChangedCallbackData(
        const std::string &switchName, int32_t userId, NotificationConstant::SWITCH_STATE enableStatus);
    ~NotificationSwitchChangedCallbackData() override = default;

    void SetUserId(int32_t userId);
    int32_t GetUserId() const;

    void SetSwitchName(const std::string &switchName);
    std::string GetSwitchName() const;

    void SetEnableStatus(NotificationConstant::SWITCH_STATE enableStatus);
    NotificationConstant::SWITCH_STATE GetEnableStatus() const;

    std::string Dump();

    bool Marshalling(Parcel &parcel) const override;
    static NotificationSwitchChangedCallbackData *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

    std::string switchName_;
    int32_t userId_ {SUBSCRIBE_USER_INIT};
    NotificationConstant::SWITCH_STATE enableStatus_ {NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_NOTIFICATION_SWITCH_CHANGED_CALLBACK_DATA_H