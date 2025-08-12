/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "notification_flags.h"

#include <string>                   // for operator+, to_string, basic_string

#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"        // for json, basic_json<>::object_t, bas...
#include "notification_constant.h"  // for NotificationConstant::FlagStatus
#include "parcel.h"                 // for Parcel

namespace OHOS {
namespace Notification {

NotificationFlags::NotificationFlags(uint32_t reminderFlags): reminderFlags_(reminderFlags)
{
    if ((NotificationConstant::ReminderFlag::SOUND_FLAG & reminderFlags) > 0) {
        soundEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        soundEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }
 
    if ((NotificationConstant::ReminderFlag::VIBRATION_FLAG & reminderFlags) > 0) {
        vibrationEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        vibrationEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }
}

void NotificationFlags::SetSoundEnabled(NotificationConstant::FlagStatus soundEnabled)
{
    if (soundEnabled == NotificationConstant::FlagStatus::OPEN) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::SOUND_FLAG;
        soundEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::SOUND_FLAG);
        soundEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }
}

NotificationConstant::FlagStatus NotificationFlags::IsSoundEnabled() const
{
    return soundEnabled_;
}

void NotificationFlags::SetVibrationEnabled(NotificationConstant::FlagStatus vibrationEnabled)
{
    if (vibrationEnabled == NotificationConstant::FlagStatus::OPEN) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
        vibrationEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::VIBRATION_FLAG);
        vibrationEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }
}

NotificationConstant::FlagStatus NotificationFlags::IsVibrationEnabled() const
{
    return vibrationEnabled_;
}

uint32_t NotificationFlags::GetReminderFlags()
{
    return reminderFlags_;
}

void NotificationFlags::SetReminderFlags(const uint32_t reminderFlag)
{
    reminderFlags_ = reminderFlag;
    if (reminderFlags_ & NotificationConstant::ReminderFlag::VIBRATION_FLAG) {
        vibrationEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        vibrationEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }

    if (reminderFlags_ & NotificationConstant::ReminderFlag::SOUND_FLAG) {
        soundEnabled_ = NotificationConstant::FlagStatus::OPEN;
    } else {
        soundEnabled_ = NotificationConstant::FlagStatus::CLOSE;
    }
}

void NotificationFlags::SetLockScreenVisblenessEnabled(bool visblenessEnabled)
{
    if (visblenessEnabled) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG);
    }
}

bool NotificationFlags::IsLockScreenVisblenessEnabled()
{
    if ((reminderFlags_ & NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG) != 0) {
        return true;
    }
    return false;
}

void NotificationFlags::SetBannerEnabled(bool bannerEnabled)
{
    if (bannerEnabled) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::BANNER_FLAG;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::BANNER_FLAG);
    }
}

bool NotificationFlags::IsBannerEnabled()
{
    if ((reminderFlags_ & NotificationConstant::ReminderFlag::BANNER_FLAG) != 0) {
        return true;
    }
    return false;
}

void NotificationFlags::SetLightScreenEnabled(bool lightScreenEnabled)
{
    if (lightScreenEnabled) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG);
    }
}

bool NotificationFlags::IsLightScreenEnabled()
{
    if ((reminderFlags_ & NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG) != 0) {
        return true;
    }
    return false;
}

void NotificationFlags::SetStatusIconEnabled(bool statusIconEnabled)
{
    if (statusIconEnabled) {
        reminderFlags_ |= NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG;
    } else {
        reminderFlags_ &= ~(NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG);
    }
}

bool NotificationFlags::IsStatusIconEnabled()
{
    if ((reminderFlags_ & NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG) != 0) {
        return true;
    }
    return false;
}

std::string NotificationFlags::Dump()
{
    return "soundEnabled = " + std::to_string(static_cast<uint8_t>(soundEnabled_)) +
           ", vibrationEnabled = " + std::to_string(static_cast<uint8_t>(vibrationEnabled_)) +
           ", reminderFlags = " + std::to_string(reminderFlags_);
}

bool NotificationFlags::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["soundEnabled"]     = soundEnabled_;
    jsonObject["vibrationEnabled"] = vibrationEnabled_;
    jsonObject["reminderFlags"] = reminderFlags_;

    return true;
}

NotificationFlags *NotificationFlags::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pFlags = new (std::nothrow) NotificationFlags();
    if (pFlags == nullptr) {
        ANS_LOGE("null pFlags");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("soundEnabled") != jsonEnd && jsonObject.at("soundEnabled").is_number_integer()) {
        auto soundEnabled  = jsonObject.at("soundEnabled").get<uint8_t>();
        pFlags->soundEnabled_ = static_cast<NotificationConstant::FlagStatus>(soundEnabled);
    }

    if (jsonObject.find("vibrationEnabled") != jsonEnd && jsonObject.at("vibrationEnabled").is_number_integer()) {
        auto vibrationEnabled = jsonObject.at("vibrationEnabled").get<uint8_t>();
        pFlags->vibrationEnabled_ = static_cast<NotificationConstant::FlagStatus>(vibrationEnabled);
    }

    if (jsonObject.find("reminderFlags") != jsonEnd && jsonObject.at("reminderFlags").is_number_integer()) {
        auto reminderFlags = jsonObject.at("reminderFlags").get<uint32_t>();
        pFlags->reminderFlags_ = reminderFlags;
    }

    return pFlags;
}

bool NotificationFlags::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint8(static_cast<uint8_t>(soundEnabled_))) {
        ANS_LOGE("Failed to write flag sound enable for the notification");
        return false;
    }

    if (!parcel.WriteUint8(static_cast<uint8_t>(vibrationEnabled_))) {
        ANS_LOGE("Failed to write flag vibration enable for the notification");
        return false;
    }

    if (!parcel.WriteUint32(reminderFlags_)) {
        ANS_LOGE("Failed to write reminder flags for the notification.");
        return false;
    }

    return true;
}

NotificationFlags *NotificationFlags::Unmarshalling(Parcel &parcel)
{
    auto templ = new (std::nothrow) NotificationFlags();
    if (templ == nullptr) {
        ANS_LOGE("null templ");
        return nullptr;
    }
    if (!templ->ReadFromParcel(parcel)) {
        delete templ;
        templ = nullptr;
    }

    return templ;
}

bool NotificationFlags::ReadFromParcel(Parcel &parcel)
{
    soundEnabled_ = static_cast<NotificationConstant::FlagStatus>(parcel.ReadUint8());
    vibrationEnabled_ = static_cast<NotificationConstant::FlagStatus>(parcel.ReadUint8());
    reminderFlags_ = parcel.ReadUint32();

    return true;
}

bool NotificationFlags::GetReminderFlagsByString(
    const std::string &strReminderFlags, std::shared_ptr<NotificationFlags> &reminderFlags)
{
    if (strReminderFlags.size() <= SOUND_ENABLED_SEQ) {
        ANS_LOGE("GetReminderFlagsByString failed as Invalid reminderFlags size");
        return false;
    }
    for (int32_t seq = 0; seq < strReminderFlags.size(); seq++) {
        if (!ValidCharReminderFlag(strReminderFlags[seq], seq)) {
            return false;
        }
    }
    if (reminderFlags == nullptr) {
        reminderFlags = std::make_shared<NotificationFlags>();
    }
    reminderFlags->SetSoundEnabled(
        static_cast<NotificationConstant::FlagStatus>(strReminderFlags[SOUND_ENABLED_SEQ] - '0'));
    reminderFlags->SetLockScreenVisblenessEnabled(
        static_cast<bool>(strReminderFlags[LOCK_SCREEN_VISIBLENESS_ENABLED_SEQ] - '0'));
    reminderFlags->SetBannerEnabled(static_cast<bool>(strReminderFlags[BANNER_ENABLED_SEQ] - '0'));
    reminderFlags->SetLightScreenEnabled(static_cast<bool>(strReminderFlags[LIGHT_SCREEN_ENABLED_SEQ] - '0'));
    reminderFlags->SetVibrationEnabled(
        static_cast<NotificationConstant::FlagStatus>(strReminderFlags[VIBRATION_ENABLED_SEQ] - '0'));
    reminderFlags->SetStatusIconEnabled(static_cast<bool>(strReminderFlags[ICON_ENABLED_SEQ] - '0'));
    return true;
}

bool NotificationFlags::ValidCharReminderFlag(const char &charReminderFlag, const int32_t &seq)
{
    if (charReminderFlag == CHAR_REMIND_DISABLE || charReminderFlag == CHAR_REMIND_ENABLE) {
        return true;
    }
    if ((seq == SOUND_ENABLED_SEQ || seq == VIBRATION_ENABLED_SEQ) && charReminderFlag == CHAR_FLAG_STATUS_CLOSE) {
        return true;
    }
    return false;
}
}  // namespace Notification
}  // namespace OHOS
