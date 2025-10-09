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

#include "notification_reminder_info.h"

#include <cstdint>
#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type


#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel

namespace OHOS {
namespace Notification {

const NotificationBundleOption& NotificationReminderInfo::GetBundleOption() const
{
    return bundle_;
}

void NotificationReminderInfo::SetBundleOption(NotificationBundleOption bundle)
{
    bundle_ = bundle;
}

uint32_t NotificationReminderInfo::GetReminderFlags() const
{
    return reminderFlags_;
}

void NotificationReminderInfo::SetReminderFlags(uint32_t reminderFlags)
{
    reminderFlags_ = reminderFlags;
}

bool NotificationReminderInfo::GetSilentReminderEnabled() const
{
    return silentReminderEnabled_;
}

void NotificationReminderInfo::SetSilentReminderEnabled(bool silentReminderEnabled)
{
    silentReminderEnabled_ = silentReminderEnabled;
}

std::string NotificationReminderInfo::Dump()
{
    return "ReminderInfo{ "
            "bundle = " + bundle_.Dump() +
            ", reminderFlags_ = " + std::to_string(reminderFlags_) +
            ", silentReminderEnabled_ = " + std::to_string(silentReminderEnabled_) +
            " }";
}

bool NotificationReminderInfo::ToJson(nlohmann::json &jsonObject) const
{
    nlohmann::json bundleObj;
    if (!NotificationJsonConverter::ConvertToJson(&bundle_, bundleObj)) {
        ANS_LOGE("Cannot convert bundleOption to JSON");
        return false;
    }
    jsonObject["bundle"] = bundleObj;
    jsonObject["reminderFlags"] = reminderFlags_;
    jsonObject["silentReminderEnabled"] = silentReminderEnabled_;

    return true;
}

NotificationReminderInfo *NotificationReminderInfo::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationReminderInfo *reminderInfo = new (std::nothrow) NotificationReminderInfo();
    if (reminderInfo == nullptr) {
        ANS_LOGE("null reminderInfo");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("bundle") != jsonEnd) {
        auto bundleObj = jsonObject.at("bundle");
        auto pBundle = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(bundleObj);
        if (pBundle != nullptr) {
            reminderInfo->bundle_ = *pBundle;
            delete pBundle;
            pBundle = nullptr;
        }
    }

    if (jsonObject.find("reminderFlags") != jsonEnd && jsonObject.at("reminderFlags").is_number_integer()) {
        reminderInfo->reminderFlags_ = jsonObject.at("reminderFlags").get<uint32_t>();
    }

    if (jsonObject.find("silentReminderEnabled") != jsonEnd && jsonObject.at("silentReminderEnabled").is_boolean()) {
        reminderInfo->silentReminderEnabled_ = jsonObject.at("silentReminderEnabled").get<bool>();
    }

    return reminderInfo;
}

bool NotificationReminderInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteParcelable(&bundle_)) {
        ANS_LOGE("Failed to write bundle");
        return false;
    }

    if (!parcel.WriteUint32(reminderFlags_)) {
        ANS_LOGE("Failed to write reminderFlags");
        return false;
    }

    if (!parcel.WriteBool(silentReminderEnabled_)) {
        ANS_LOGE("Failed to write silentReminderEnabled");
        return false;
    }
    return true;
}

bool NotificationReminderInfo::ReadFromParcel(Parcel &parcel)
{
    auto pBundle = parcel.ReadParcelable<NotificationBundleOption>();
    if (pBundle == nullptr) {
        ANS_LOGE("null BundleOption");
        return false;
    }
    bundle_ = *pBundle;
    delete pBundle;
    pBundle = nullptr;

    reminderFlags_ = parcel.ReadUint32();
    silentReminderEnabled_ = parcel.ReadBool();

    return true;
}

NotificationReminderInfo *NotificationReminderInfo::Unmarshalling(Parcel &parcel)
{
    NotificationReminderInfo *reminderInfo = new (std::nothrow) NotificationReminderInfo();

    if (reminderInfo && !reminderInfo->ReadFromParcel(parcel)) {
        delete reminderInfo;
        reminderInfo = nullptr;
    }

    return reminderInfo;
}
}  // namespace Notification
}  // namespace OHOS
