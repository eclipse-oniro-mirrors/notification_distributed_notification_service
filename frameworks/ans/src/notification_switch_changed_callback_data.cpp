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

#include "notification_switch_changed_callback_data.h"

#include "ans_log_wrapper.h"
#include "string_ex.h"

#include <string>

namespace OHOS {
namespace Notification {
NotificationSwitchChangedCallbackData::NotificationSwitchChangedCallbackData(
    const std::string &switchName, int32_t userId, NotificationConstant::SWITCH_STATE enableStatus)
    : switchName_(switchName), userId_(userId), enableStatus_(enableStatus)
{}

void NotificationSwitchChangedCallbackData::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t NotificationSwitchChangedCallbackData::GetUserId() const
{
    return userId_;
}

void NotificationSwitchChangedCallbackData::SetSwitchName(const std::string &switchName)
{
    switchName_ = switchName;
}

std::string NotificationSwitchChangedCallbackData::GetSwitchName() const
{
    return switchName_;
}

void NotificationSwitchChangedCallbackData::SetEnableStatus(NotificationConstant::SWITCH_STATE enableStatus)
{
    enableStatus_ = enableStatus;
}

NotificationConstant::SWITCH_STATE NotificationSwitchChangedCallbackData::GetEnableStatus() const
{
    return enableStatus_;
}

std::string NotificationSwitchChangedCallbackData::Dump()
{
    return "NotificationSwitchChangedCallbackData{ "
        "userId = " + std::to_string(userId_) +
        ", switchName = " + switchName_ +
        ", enableStatus = " + std::to_string(static_cast<int32_t>(enableStatus_)) +
        " }";
}

bool NotificationSwitchChangedCallbackData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(userId_)) {
        ANS_LOGE("Failed to write userId");
        return false;
    }

    if (!parcel.WriteString(switchName_)) {
        ANS_LOGE("Failed to write switchName");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(enableStatus_))) {
        ANS_LOGE("Failed to write enableStatus");
        return false;
    }

    return true;
}

NotificationSwitchChangedCallbackData *NotificationSwitchChangedCallbackData::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationSwitchChangedCallbackData();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool NotificationSwitchChangedCallbackData::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(userId_)) {
        ANS_LOGE("Failed to read userId");
        return false;
    }
    if (!parcel.ReadString(switchName_)) {
        ANS_LOGE("Failed to read switchName");
        return false;
    }
    int32_t enableStatus = 0;
    if (!parcel.ReadInt32(enableStatus)) {
        ANS_LOGE("Failed to read enableStatus");
        return false;
    }
    enableStatus_ = static_cast<NotificationConstant::SWITCH_STATE>(enableStatus);
    return true;
}
}  // namespace Notification
}  // namespace OHOS