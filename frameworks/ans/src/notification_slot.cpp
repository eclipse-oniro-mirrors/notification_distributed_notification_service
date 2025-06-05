/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "notification_slot.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
std::map<std::string, NotificationConstant::SlotType> NotificationSlot::convertStrToSlotType_ = {
    {SOCIAL_COMMUNICATION, NotificationConstant::SlotType::SOCIAL_COMMUNICATION},
    {SERVICE_REMINDER, NotificationConstant::SlotType::SERVICE_REMINDER},
    {CONTENT_INFORMATION, NotificationConstant::SlotType::CONTENT_INFORMATION},
    {OTHER, NotificationConstant::SlotType::OTHER},
    {LIVE_VIEW, NotificationConstant::SlotType::LIVE_VIEW},
    {CUSTOM_SERVICE, NotificationConstant::SlotType::CUSTOMER_SERVICE},
    {EMERGENCY_INFORMATION, NotificationConstant::SlotType::EMERGENCY_INFORMATION}
};

const int32_t MAX_TEXT_LENGTH = 1000;
const uint32_t SOUND_OPNE = 1 << 0;
const uint32_t LOCKSCREEN_OPNE = 1 << 1;
const uint32_t BANNER_OPNE = 1 << 2;
const uint32_t LIGHTSCREEN_OPNE = 1 << 3;
const uint32_t VIBRATION_OPNE = 1 << 4;
const uint32_t STATUSBAR_ICON_OPNE = 1 << 5;

NotificationSlot::NotificationSlot(NotificationConstant::SlotType type) : sound_("")
{
    SetType(type);
}

NotificationSlot::~NotificationSlot()
{}

bool NotificationSlot::CanEnableLight() const
{
    return isLightEnabled_;
}

void NotificationSlot::SetEnableLight(bool isLightEnabled)
{
    isLightEnabled_ = isLightEnabled;
}

bool NotificationSlot::CanVibrate() const
{
    return isVibrationEnabled_;
}

void NotificationSlot::SetEnableVibration(bool vibration)
{
    isVibrationEnabled_ = vibration;
}

std::string NotificationSlot::GetDescription() const
{
    return description_;
}

void NotificationSlot::SetDescription(const std::string &description)
{
    description_ = TruncateString(description);
}

std::string NotificationSlot::GetId() const
{
    return id_;
}

int32_t NotificationSlot::GetLedLightColor() const
{
    return lightColor_;
}

void NotificationSlot::SetLedLightColor(int32_t color)
{
    lightColor_ = color;
}

NotificationSlot::NotificationLevel NotificationSlot::GetLevel() const
{
    return level_;
}

void NotificationSlot::SetLevel(NotificationLevel level)
{
    level_ = level;
}

NotificationConstant::SlotType NotificationSlot::GetType() const
{
    return type_;
}

int32_t NotificationSlot::GetAuthorizedStatus() const
{
    return authorizedStatus_;
}

void NotificationSlot::SetAuthorizedStatus(int32_t status)
{
    authorizedStatus_ = status;
}

int32_t NotificationSlot::GetAuthHintCnt() const
{
    return authHintCnt_;
}

void NotificationSlot::AddAuthHintCnt()
{
    authHintCnt_++;
}

void NotificationSlot::SetAuthHintCnt(int32_t count)
{
    authHintCnt_ = count;
}


void NotificationSlot::SetType(NotificationConstant::SlotType type)
{
    type_ = NotificationConstant::SlotType::CUSTOM;
    switch (type) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            id_ = "SOCIAL_COMMUNICATION";
            SetName("SOCIAL_COMMUNICATION");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
            SetSound(DEFAULT_NOTIFICATION_SOUND);
            SetVibrationStyle(DEFAULT_NOTIFICATION_VIBRATION);
            SetLevel(LEVEL_HIGH);
            break;
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            id_ = "SERVICE_REMINDER";
            SetName("SERVICE_REMINDER");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
            SetSound(DEFAULT_NOTIFICATION_SOUND);
            SetVibrationStyle(DEFAULT_NOTIFICATION_VIBRATION);
            SetLevel(LEVEL_DEFAULT);
            break;
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            id_ = "CONTENT_INFORMATION";
            SetName("CONTENT_INFORMATION");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::SECRET);
            SetEnableVibration(false);
            SetLevel(LEVEL_MIN);
            break;
        case NotificationConstant::SlotType::LIVE_VIEW:
            id_ = "LIVE_VIEW";
            SetName("LIVE_VIEW");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
            SetSound(DEFAULT_NOTIFICATION_SOUND);
            SetVibrationStyle(DEFAULT_NOTIFICATION_VIBRATION);
            SetLevel(LEVEL_DEFAULT);
            SetForceControl(true);
            break;
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            id_ = "CUSTOMER_SERVICE";
            SetName("CUSTOMER_SERVICE");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::SECRET);
            SetSound(DEFAULT_NOTIFICATION_SOUND);
            SetEnableVibration(false);
            SetLevel(LEVEL_LOW);
            break;
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            id_ = "EMERGENCY_INFORMATION";
            SetName("EMERGENCY_INFORMATION");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::PUBLIC);
            SetSound(DEFAULT_NOTIFICATION_SOUND);
            SetVibrationStyle(DEFAULT_NOTIFICATION_VIBRATION);
            SetLevel(LEVEL_HIGH);
            break;
        case NotificationConstant::SlotType::OTHER:
            id_ = "OTHER";
            SetName("OTHER");
            SetLockscreenVisibleness(NotificationConstant::VisiblenessType::SECRET);
            SetEnableVibration(false);
            SetLevel(LEVEL_MIN);
            break;
        default:
            break;
    }
    type_ = type;
}

NotificationConstant::VisiblenessType NotificationSlot::GetLockScreenVisibleness() const
{
    return lockScreenVisibleness_;
}

void NotificationSlot::SetLockscreenVisibleness(NotificationConstant::VisiblenessType visibleness)
{
    lockScreenVisibleness_ = visibleness;
}

std::string NotificationSlot::GetName() const
{
    return name_;
}

void NotificationSlot::SetName(const std::string &name)
{
    name_ = TruncateString(name);
}

Uri NotificationSlot::GetSound() const
{
    return sound_;
}

void NotificationSlot::SetSound(const Uri &sound)
{
    sound_ = sound;
}

std::vector<int64_t> NotificationSlot::GetVibrationStyle() const
{
    return vibrationValues_;
}

void NotificationSlot::SetVibrationStyle(const std::vector<int64_t> &vibrationValues)
{
    isVibrationEnabled_ = (vibrationValues.size() > 0);
    vibrationValues_ = vibrationValues;
}

bool NotificationSlot::IsEnableBypassDnd() const
{
    return isBypassDnd_;
}

void NotificationSlot::EnableBypassDnd(bool isBypassDnd)
{
    isBypassDnd_ = isBypassDnd;
}

bool NotificationSlot::IsShowBadge() const
{
    return isShowBadge_;
}

void NotificationSlot::EnableBadge(bool isShowBadge)
{
    isShowBadge_ = isShowBadge;
}

void NotificationSlot::SetEnable(bool enabled)
{
    enabled_ = enabled;
}

bool NotificationSlot::GetEnable() const
{
    return enabled_;
}

void NotificationSlot::SetSlotFlags(uint32_t slotFlags)
{
    slotFlags_ = slotFlags;
}

uint32_t NotificationSlot::GetSlotFlags() const
{
    return slotFlags_;
}

void NotificationSlot::SetForceControl(bool isForceControl)
{
    isForceControl_ = isForceControl;
}

bool NotificationSlot::GetForceControl() const
{
    return isForceControl_;
}

void NotificationSlot::SetReminderMode(uint32_t reminderMode)
{
    reminderMode_ = reminderMode;
}

uint32_t NotificationSlot::GetReminderMode() const
{
    if (reminderMode_ != INVALID_REMINDER_MODE) {
        return reminderMode_;
    }
    return GetDefaultReminderMode();
}

std::string NotificationSlot::Dump() const
{
    return "NotificationSlot{ "
            "id = " + id_ +
            ", name = " + name_ +
            ", description = " + description_ +
            ", type = " + std::to_string(static_cast<int32_t>(type_)) +
            ", level = " + std::to_string(static_cast<int32_t>(level_)) +
            ", isBypassDnd = " + (isBypassDnd_ ? "true" : "false") +
            ", visibleness = " + std::to_string(static_cast<int32_t>(lockScreenVisibleness_)) +
            ", sound = " + sound_.ToString() +
            ", isLightEnabled = " + (isLightEnabled_ ? "true" : "false") +
            ", lightColor = " + std::to_string(lightColor_) +
            ", isVibrate = " + (isVibrationEnabled_ ? "true" : "false") +
            ", vibration = " + MergeVectorToString(vibrationValues_) +
            ", isShowBadge = " + (isShowBadge_ ? "true" : "false") +
            ", enabled = " + (enabled_ ? "true" : "false") +
            ", slotFlags = " + std::to_string(static_cast<int32_t>(slotFlags_)) +
            ", remindMode = " + std::to_string(static_cast<int32_t>(GetReminderMode())) +
            " }";
}

bool NotificationSlot::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(id_)) {
        ANS_LOGE("Failed to write id");
        return false;
    }

    if (!parcel.WriteString(name_)) {
        ANS_LOGE("Failed to write name");
        return false;
    }

    if (!parcel.WriteBool(isLightEnabled_)) {
        ANS_LOGE("Failed to write isLightEnabled");
        return false;
    }

    if (!parcel.WriteBool(isVibrationEnabled_)) {
        ANS_LOGE("Failed to write isVibrationEnabled");
        return false;
    }

    if (!parcel.WriteBool(isShowBadge_)) {
        ANS_LOGE("Failed to write isShowBadge");
        return false;
    }

    if (!parcel.WriteBool(isBypassDnd_)) {
        ANS_LOGE("Failed to write isBypassDnd");
        return false;
    }

    if (!parcel.WriteString(description_)) {
        ANS_LOGE("Failed to write description");
        return false;
    }

    if (!parcel.WriteInt32(lightColor_)) {
        ANS_LOGE("Failed to write lightColor");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(level_))) {
        ANS_LOGE("Failed to write level");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ANS_LOGE("Failed to write type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(lockScreenVisibleness_))) {
        ANS_LOGE("Failed to write lockScreenVisibleness");
        return false;
    }

    if (sound_.ToString().empty()) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            ANS_LOGE("Failed to write VALUE_NULL");
            return false;
        }
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            ANS_LOGE("Failed to write VALUE_OBJECT");
            return false;
        }
        if (!parcel.WriteString((sound_.ToString()))) {
            ANS_LOGE("Failed to write sound");
            return false;
        }
    }

    if (!parcel.WriteInt64Vector(vibrationValues_)) {
        ANS_LOGE("Failed to write vibrationValues");
        return false;
    }

    if (!parcel.WriteBool(enabled_)) {
        ANS_LOGE("Failed to write isShowBadge");
        return false;
    }

    if (!parcel.WriteInt32(slotFlags_)) {
        ANS_LOGE("Failed to write slotFlags");
        return false;
    }

    if (!parcel.WriteInt32(authorizedStatus_)) {
        ANS_LOGE("Failed to write authorizedStatus");
        return false;
    }

    if (!parcel.WriteInt32(authHintCnt_)) {
        ANS_LOGE("Failed to write authHintCnt");
        return false;
    }

    if (!parcel.WriteInt32(reminderMode_)) {
        ANS_LOGE("Failed to write reminderMode");
        return false;
    }

    return true;
}

bool NotificationSlot::ReadFromParcel(Parcel &parcel)
{
    id_ = parcel.ReadString();
    name_ = parcel.ReadString();
    isLightEnabled_ = parcel.ReadBool();
    isVibrationEnabled_ = parcel.ReadBool();
    isShowBadge_ = parcel.ReadBool();
    isBypassDnd_ = parcel.ReadBool();
    description_ = parcel.ReadString();
    lightColor_ = parcel.ReadInt32();
    level_ = static_cast<NotificationLevel>(parcel.ReadInt32());
    type_ = static_cast<NotificationConstant::SlotType>(parcel.ReadInt32());
    lockScreenVisibleness_ = static_cast<NotificationConstant::VisiblenessType>(parcel.ReadInt32());

    int32_t empty = VALUE_NULL;
    if (!parcel.ReadInt32(empty)) {
        ANS_LOGE("Failed to read int");
        return false;
    }

    if (empty == VALUE_OBJECT) {
        sound_ = Uri((parcel.ReadString()));
    }

    parcel.ReadInt64Vector(&vibrationValues_);
    enabled_ = parcel.ReadBool();
    slotFlags_ = parcel.ReadInt32();
    authorizedStatus_ = parcel.ReadInt32();
    authHintCnt_ = parcel.ReadInt32();
    reminderMode_ = parcel.ReadInt32();
    return true;
}

NotificationSlot *NotificationSlot::Unmarshalling(Parcel &parcel)
{
    NotificationSlot *notificationSlot = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::CUSTOM);

    if (notificationSlot && !notificationSlot->ReadFromParcel(parcel)) {
        delete notificationSlot;
        notificationSlot = nullptr;
    }

    return notificationSlot;
}

std::string NotificationSlot::MergeVectorToString(const std::vector<int64_t> &mergeVector) const
{
    std::string contents;
    for (auto it = mergeVector.begin(); it != mergeVector.end(); ++it) {
        contents += std::to_string(*it);
        if (it != mergeVector.end() - 1) {
            contents += ", ";
        }
    }
    return contents;
}

std::string NotificationSlot::TruncateString(const std::string &in)
{
    std::string temp = in;
    if (in.length() > MAX_TEXT_LENGTH) {
        temp = in.substr(0, MAX_TEXT_LENGTH);
    }
    return temp;
}

bool NotificationSlot::GetSlotTypeByString(
    const std::string &strSlotType, NotificationConstant::SlotType &slotType)
{
    auto iterSlotType = convertStrToSlotType_.find(strSlotType);
    if (iterSlotType != convertStrToSlotType_.end()) {
        slotType = iterSlotType->second;
        return true;
    }
    ANS_LOGE("GetSlotTypeByString failed as Invalid strSlotType.");
    return false;
}

uint32_t NotificationSlot::GetDefaultReminderMode() const
{
    uint32_t reminderMode = 0;
    switch (type_) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            reminderMode = SOUND_OPNE + LOCKSCREEN_OPNE + BANNER_OPNE + LIGHTSCREEN_OPNE +
                VIBRATION_OPNE + STATUSBAR_ICON_OPNE;
            break;
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            reminderMode = SOUND_OPNE + LOCKSCREEN_OPNE + BANNER_OPNE + LIGHTSCREEN_OPNE +
                VIBRATION_OPNE + STATUSBAR_ICON_OPNE;
            break;
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            reminderMode = 0;
            break;
        case NotificationConstant::SlotType::LIVE_VIEW:
            reminderMode = SOUND_OPNE + LOCKSCREEN_OPNE + VIBRATION_OPNE + STATUSBAR_ICON_OPNE + LIGHTSCREEN_OPNE;
            break;
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            reminderMode = SOUND_OPNE + VIBRATION_OPNE + STATUSBAR_ICON_OPNE;
            break;
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            reminderMode = SOUND_OPNE + LOCKSCREEN_OPNE + BANNER_OPNE + LIGHTSCREEN_OPNE +
                VIBRATION_OPNE + STATUSBAR_ICON_OPNE;
            break;
        case NotificationConstant::SlotType::OTHER:
            reminderMode = 0;
            break;
        default:
            break;
    }

    return reminderMode;
}
}  // namespace Notification
}  // namespace OHOS
