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

#include "badge_number_callback_data.h"

#include <string>

#include "ans_log_wrapper.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Notification {
BadgeNumberCallbackData::BadgeNumberCallbackData(const std::string &bundle, int32_t uid, int32_t badgeNumber)
    : bundle_(bundle), uid_(uid), badgeNumber_(badgeNumber)
{}

BadgeNumberCallbackData::BadgeNumberCallbackData(const std::string &bundle, const std::string &appInstanceKey,
    int32_t uid, int32_t badgeNumber, int32_t instanceKey)
    : bundle_(bundle), appInstanceKey_(appInstanceKey), uid_(uid), badgeNumber_(badgeNumber), instanceKey_(instanceKey)
{}

void BadgeNumberCallbackData::SetBundle(const std::string &bundle)
{
    bundle_ = bundle;
}

std::string BadgeNumberCallbackData::GetBundle() const
{
    return bundle_;
}

void BadgeNumberCallbackData::SetUid(int32_t uid)
{
    uid_ = uid;
}

int32_t BadgeNumberCallbackData::GetUid() const
{
    return uid_;
}

void BadgeNumberCallbackData::SetBadgeNumber(int32_t badgeNumber)
{
    badgeNumber_ = badgeNumber;
}

int32_t BadgeNumberCallbackData::GetBadgeNumber() const
{
    return badgeNumber_;
}

void BadgeNumberCallbackData::SetInstanceKey(int32_t key)
{
    instanceKey_ = key;
}

int32_t BadgeNumberCallbackData::GetInstanceKey() const
{
    return instanceKey_;
}

void BadgeNumberCallbackData::SetAppInstanceKey(const std::string &key)
{
    appInstanceKey_ = key;
}
 
std::string BadgeNumberCallbackData::GetAppInstanceKey() const
{
    return appInstanceKey_;
}

std::string BadgeNumberCallbackData::Dump()
{
    return "BadgeNumberCallbackData{ "
            "bundle = " + bundle_ +
            ", uid = " + std::to_string(uid_) +
            ", badgeNumber = " + std::to_string(badgeNumber_) +
            ", instanceKey = " + appInstanceKey_ +
            " }";
}

bool BadgeNumberCallbackData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(bundle_))) {
        ANS_LOGE("Failed to write bundle name");
        return false;
    }

    if (!parcel.WriteString(appInstanceKey_)) {
        ANS_LOGE("Failed to write app instance Key name");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    if (!parcel.WriteInt32(badgeNumber_)) {
        ANS_LOGE("Failed to write badgeNumber");
        return false;
    }

    if (!parcel.WriteInt32(instanceKey_)) {
        ANS_LOGE("Failed to write instanceKey");
        return false;
    }

    return true;
}

BadgeNumberCallbackData *BadgeNumberCallbackData::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) BadgeNumberCallbackData();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }

    return objptr;
}

bool BadgeNumberCallbackData::ReadFromParcel(Parcel &parcel)
{
    bundle_ = Str16ToStr8(parcel.ReadString16());
    appInstanceKey_ = parcel.ReadString();
    uid_ = parcel.ReadInt32();
    badgeNumber_ = parcel.ReadInt32();
    instanceKey_ = parcel.ReadInt32();

    return true;
}
}  // namespace Notification
}  // namespace OHOS