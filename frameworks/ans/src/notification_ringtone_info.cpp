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

#include "notification_ringtone_info.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *RINGTONE_INFO_RINGTONE_TYPE = "ringtoneType";
constexpr const char *RINGTONE_INFO_RINGTONE_TITLE = "ringtoneTitle";
constexpr const char *RINGTONE_INFO_RINGTONE_FILE_NAME = "ringtoneFileName";
constexpr const char *RINGTONE_INFO_RINGTONE_URI = "ringtoneUri";
} // namespace
NotificationRingtoneInfo::NotificationRingtoneInfo(NotificationConstant::RingtoneType ringtoneType,
    const std::string &ringtoneTitle, const std::string &ringtoneFileName, const std::string &ringtoneUri)
    : ringtoneType_(ringtoneType), ringtoneTitle_(ringtoneTitle), ringtoneFileName_(ringtoneFileName),
    ringtoneUri_(ringtoneUri)
{}

void NotificationRingtoneInfo::SetRingtoneType(NotificationConstant::RingtoneType ringtoneType)
{
    ringtoneType_ = ringtoneType;
}

NotificationConstant::RingtoneType NotificationRingtoneInfo::GetRingtoneType() const
{
    return ringtoneType_;
}

void NotificationRingtoneInfo::SetRingtoneTitle(const std::string &ringtoneTitle)
{
    ringtoneTitle_ = ringtoneTitle;
}

std::string NotificationRingtoneInfo::GetRingtoneTitle() const
{
    return ringtoneTitle_;
}

void NotificationRingtoneInfo::SetRingtoneFileName(const std::string &ringtoneFileName)
{
    ringtoneFileName_ = ringtoneFileName;
}

std::string NotificationRingtoneInfo::GetRingtoneFileName() const
{
    return ringtoneFileName_;
}

void NotificationRingtoneInfo::ResetRingtone()
{
    ringtoneType_ = NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT;
    ringtoneTitle_ = "";
    ringtoneFileName_ = "";
    ringtoneUri_ = "";
}

void NotificationRingtoneInfo::SetRingtoneUri(const std::string &ringtoneUri)
{
    ringtoneUri_ = ringtoneUri;
}

std::string NotificationRingtoneInfo::GetRingtoneUri() const
{
    return ringtoneUri_;
}

bool NotificationRingtoneInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(ringtoneType_))) {
        ANS_LOGE("Failed to write ringtone type");
        return false;
    }

    if (!parcel.WriteString(ringtoneTitle_)) {
        ANS_LOGE("Failed to write ringtone title");
        return false;
    }

    if (!parcel.WriteString(ringtoneFileName_)) {
        ANS_LOGE("Failed to write ringtone file name");
        return false;
    }

    if (!parcel.WriteString(ringtoneUri_)) {
        ANS_LOGE("Failed to write ringtone uri");
        return false;
    }

    return true;
}

NotificationRingtoneInfo *NotificationRingtoneInfo::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationRingtoneInfo();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool NotificationRingtoneInfo::ReadFromParcel(Parcel &parcel)
{
    ringtoneType_ = static_cast<NotificationConstant::RingtoneType>(parcel.ReadInt32());
    ringtoneTitle_ = parcel.ReadString();
    ringtoneFileName_ = parcel.ReadString();
    ringtoneUri_ = parcel.ReadString();
    return true;
}

std::string NotificationRingtoneInfo::ToJson()
{
    nlohmann::json jsonObject;
    jsonObject[RINGTONE_INFO_RINGTONE_TYPE] = static_cast<int32_t>(ringtoneType_);
    jsonObject[RINGTONE_INFO_RINGTONE_TITLE] = ringtoneTitle_;
    jsonObject[RINGTONE_INFO_RINGTONE_FILE_NAME] = ringtoneFileName_;
    jsonObject[RINGTONE_INFO_RINGTONE_URI] = ringtoneUri_;
    return jsonObject.dump();
}

void NotificationRingtoneInfo::FromJson(const std::string &jsonObj)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonObj, nullptr, false);
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }
    if (jsonObject.is_discarded()) {
        ANS_LOGE("Failed to parse json string.");
        return;
    }
    if (jsonObject.contains(RINGTONE_INFO_RINGTONE_TYPE) && jsonObject[RINGTONE_INFO_RINGTONE_TYPE].is_number()) {
        ringtoneType_ =
            static_cast<NotificationConstant::RingtoneType>(jsonObject.at(RINGTONE_INFO_RINGTONE_TYPE).get<int32_t>());
    }
    if (jsonObject.contains(RINGTONE_INFO_RINGTONE_TITLE) && jsonObject[RINGTONE_INFO_RINGTONE_TITLE].is_string()) {
        ringtoneTitle_ = jsonObject.at(RINGTONE_INFO_RINGTONE_TITLE).get<std::string>();
    }
    if (jsonObject.contains(RINGTONE_INFO_RINGTONE_FILE_NAME) &&
        jsonObject[RINGTONE_INFO_RINGTONE_FILE_NAME].is_string()) {
        ringtoneFileName_ = jsonObject.at(RINGTONE_INFO_RINGTONE_FILE_NAME).get<std::string>();
    }
    if (jsonObject.contains(RINGTONE_INFO_RINGTONE_URI) && jsonObject[RINGTONE_INFO_RINGTONE_URI].is_string()) {
        ringtoneUri_ = jsonObject.at(RINGTONE_INFO_RINGTONE_URI).get<std::string>();
    }
}

std::string NotificationRingtoneInfo::Dump() const
{
    return std::to_string(static_cast<int32_t>(ringtoneType_)) + " " + ringtoneTitle_ + " " + ringtoneFileName_ +
        " " + ringtoneUri_;
}
}  // namespace Notification
}  // namespace OHOS
