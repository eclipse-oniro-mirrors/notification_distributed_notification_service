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

#include "enabled_silent_reminder_callback_data.h"

#include <string>

#include "ans_log_wrapper.h"
#include "string_ex.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
EnabledSilentReminderCallbackData::EnabledSilentReminderCallbackData(
    std::string bundle, uid_t uid, NotificationConstant::SWITCH_STATE enableStatus)
    : bundle_(bundle), uid_(uid), enableStatus_(enableStatus)
{}

void EnabledSilentReminderCallbackData::SetBundle(const std::string &bundle)
{
    bundle_ = bundle;
}

std::string EnabledSilentReminderCallbackData::GetBundle() const
{
    return bundle_;
}

void EnabledSilentReminderCallbackData::SetUid(const uid_t uid)
{
    uid_ = uid;
}

uid_t EnabledSilentReminderCallbackData::GetUid() const
{
    return uid_;
}

void EnabledSilentReminderCallbackData::SetEnableStatus(
    const NotificationConstant::SWITCH_STATE enableStatus)
{
    enableStatus_ = enableStatus;
}

NotificationConstant::SWITCH_STATE EnabledSilentReminderCallbackData::GetEnableStatus() const
{
    return enableStatus_;
}

std::string EnabledSilentReminderCallbackData::Dump()
{
    return "EnabledSilentReminderCallbackData{ "
            "bundle = " + bundle_ +
            ", uid = " + std::to_string(uid_) +
            ", enableStatus = " + std::to_string(static_cast<int32_t>(enableStatus_)) +
            " }";
}

bool EnabledSilentReminderCallbackData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(bundle_))) {
        ANS_LOGE("Failed to write bundle name");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(enableStatus_))) {
        ANS_LOGE("Failed to write enableStatus");
        return false;
    }

    return true;
}

EnabledSilentReminderCallbackData *EnabledSilentReminderCallbackData::Unmarshalling(
    Parcel &parcel)
{
    auto objptr = new (std::nothrow) EnabledSilentReminderCallbackData();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool EnabledSilentReminderCallbackData::ReadFromParcel(Parcel &parcel)
{
    bundle_ = Str16ToStr8(parcel.ReadString16());
    uid_ = static_cast<uid_t>(parcel.ReadInt32());
    enableStatus_ = static_cast<NotificationConstant::SWITCH_STATE>(parcel.ReadInt32());
    return true;
}
}  // namespace Notification
}  // namespace OHOS