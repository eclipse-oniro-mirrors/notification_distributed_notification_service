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

#include "notification.h"

#include <sstream>

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
Notification::Notification() {};

Notification::Notification(const sptr<NotificationRequest> &request)
{
    if (request != nullptr) {
        isRemoveAllowed_ = request->IsRemoveAllowed();
    }
    request_ = request;
    if (request != nullptr) {
        key_ = request->GetBaseKey("");
    }
}

Notification::Notification(const std::string &deviceId, const sptr<NotificationRequest> &request)
{
    deviceId_ = deviceId;
    request_ = request;
    if (request != nullptr) {
        key_ = request->GetBaseKey(deviceId);
    }
}

Notification::Notification(const Notification &other)
{
    enableSound_ = other.enableSound_;
    enableLight_ = other.enableLight_;
    enableVibration_ = other.enableVibration_;
    key_ = other.key_;
    ledLightColor_ = other.ledLightColor_;
    lockscreenVisibleness_ = other.lockscreenVisibleness_;
    remindType_ = other.remindType_;
    request_ = other.request_;
    postTime_ = other.postTime_;
    sound_ = other.sound_;
    vibrationStyle_ = other.vibrationStyle_;
    isRemoveAllowed_ = other.isRemoveAllowed_;
    sourceType_ = other.sourceType_;
    deviceId_ = other.deviceId_;
    updateTimerId_ = other.updateTimerId_;
    finishTimerId_ = other.finishTimerId_;
    archiveTimerId_ = other.archiveTimerId_;
    isPrivileged_ = other.isPrivileged_;
}

Notification::~Notification()
{}

bool Notification::EnableLight() const
{
    return enableLight_;
}

bool Notification::EnableSound() const
{
    return enableSound_;
}

bool Notification::EnableVibrate() const
{
    return enableVibration_;
}

std::string Notification::GetBundleName() const
{
    if (request_ == nullptr) {
        return "";
    }
    return request_->GetOwnerBundleName();
}

std::string Notification::GetCreateBundle() const
{
    if (request_ == nullptr) {
        return "";
    }
    return request_->GetCreatorBundleName();
}

std::string Notification::GetLabel() const
{
    if (request_ == nullptr) {
        return "";
    }
    return request_->GetLabel();
}

int32_t Notification::GetLedLightColor() const
{
    return ledLightColor_;
}

NotificationConstant::VisiblenessType Notification::GetLockscreenVisibleness() const
{
    return lockscreenVisibleness_;
}

std::string Notification::GetGroup() const
{
    if (request_ == nullptr) {
        return "";
    }
    return request_->GetGroupName();
}

int32_t Notification::GetId() const
{
    if (request_ == nullptr) {
        return -1;
    }
    return request_->GetNotificationId();
}

std::string Notification::GetKey() const
{
    return key_;
}

void Notification::SetKey(const std::string& key)
{
    key_ = key;
}

NotificationRequest Notification::GetNotificationRequest() const
{
    return *request_;
}

sptr<NotificationRequest> Notification::GetNotificationRequestPoint() const
{
    return request_;
}

int64_t Notification::GetPostTime() const
{
    return postTime_;
}

Uri Notification::GetSound() const
{
    if (enableSound_ && sound_ != nullptr) {
        return *sound_;
    }
    return Uri("");
}

int32_t Notification::GetUid() const
{
    if (request_ == nullptr) {
        return 0;
    }
    return request_->GetCreatorUid();
}

pid_t Notification::GetPid() const
{
    if (request_ == nullptr) {
        return 0;
    }
    return request_->GetCreatorPid();
}

bool Notification::IsUnremovable() const
{
    if (request_ == nullptr) {
        return false;
    }
    return request_->IsUnremovable();
}

std::vector<int64_t> Notification::GetVibrationStyle() const
{
    return vibrationStyle_;
}

bool Notification::IsGroup() const
{
    if (request_ == nullptr) {
        return false;
    }
    return !(request_->GetGroupName() == "");
}

bool Notification::IsFloatingIcon() const
{
    if (request_ == nullptr) {
        return false;
    }
    return request_->IsFloatingIcon();
}

NotificationConstant::RemindType Notification::GetRemindType() const
{
    return remindType_;
}

bool Notification::IsRemoveAllowed() const
{
    return isRemoveAllowed_;
}

NotificationConstant::SourceType Notification::GetSourceType() const
{
    return sourceType_;
}

std::string Notification::GetDeviceId() const
{
    return deviceId_;
}

int32_t Notification::GetUserId() const
{
    if (request_ == nullptr) {
        return 0;
    }
    return request_->GetCreatorUserId();
}

int32_t Notification::GetRecvUserId() const
{
    if (request_ == nullptr) {
        return 0;
    }
    return request_->GetReceiverUserId();
}

std::string Notification::GetInstanceKey() const
{
    if (request_ == nullptr) {
        return "";
    }
    return request_->GetAppInstanceKey();
}

bool Notification::GetPrivileged() const
{
    return isPrivileged_;
}

bool Notification::MarshallingBool(Parcel &parcel) const
{
    if (!parcel.WriteBool(enableLight_)) {
        ANS_LOGE("Can't write enableLight_");
        return false;
    }

    if (!parcel.WriteBool(enableSound_)) {
        ANS_LOGE("Can't write enableSound_");
        return false;
    }

    if (!parcel.WriteBool(enableVibration_)) {
        ANS_LOGE("Can't write enableVibration_");
        return false;
    }

    if (!parcel.WriteBool(isRemoveAllowed_)) {
        ANS_LOGE("Can't write isRemoveAllowed");
        return false;
    }

    if (!parcel.WriteBool(isPrivileged_)) {
        ANS_LOGE("Can't write isPrivileged");
        return false;
    }

    return true;
}

bool Notification::MarshallingString(Parcel &parcel) const
{
    if (!parcel.WriteString(key_)) {
        ANS_LOGE("Can't write key");
        return false;
    }

    if (enableSound_ && sound_ != nullptr) {
        if (!parcel.WriteString(sound_->ToString())) {
            ANS_LOGE("Can't write sound");
            return false;
        }
    }

    if (!parcel.WriteString(deviceId_)) {
        ANS_LOGE("Can't write deviceId");
        return false;
    }

    return true;
}

bool Notification::MarshallingInt32(Parcel &parcel) const
{
    if (!parcel.WriteInt32(ledLightColor_)) {
        ANS_LOGE("Can't write ledLightColor");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(lockscreenVisibleness_))) {
        ANS_LOGE("Can't write visbleness");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(remindType_))) {
        ANS_LOGE("Can't write remindType");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(sourceType_))) {
        ANS_LOGE("Can't write sourceType");
        return false;
    }

    return true;
}

bool Notification::MarshallingInt64(Parcel &parcel) const
{
    if (!parcel.WriteInt64(postTime_)) {
        ANS_LOGE("Can't write postTime");
        return false;
    }

    if (!parcel.WriteInt64Vector(vibrationStyle_)) {
        ANS_LOGE("Can't write vibrationStyle");
        return false;
    }

    return true;
}

bool Notification::MarshallingUint64(Parcel &parcel) const
{
    if (!parcel.WriteUint64(updateTimerId_)) {
        ANS_LOGE("Can't write update timer id.");
        return false;
    }

    if (!parcel.WriteUint64(finishTimerId_)) {
        ANS_LOGE("Can't write finish timer id.");
        return false;
    }

    if (!parcel.WriteUint64(archiveTimerId_)) {
        ANS_LOGE("Can't write archive timer id.");
        return false;
    }

    return true;
}

bool Notification::MarshallingParcelable(Parcel &parcel) const
{
    if (!parcel.WriteStrongParcelable(request_)) {
        ANS_LOGE("Can't write request");
        return false;
    }

    return true;
}

bool Notification::Marshalling(Parcel &parcel) const
{
    if (!MarshallingBool(parcel)) {
        return false;
    }
    if (!MarshallingString(parcel)) {
        return false;
    }
    if (!MarshallingInt32(parcel)) {
        return false;
    }
    if (!MarshallingInt64(parcel)) {
        return false;
    }
    if (!MarshallingUint64(parcel)) {
        return false;
    }
    if (!MarshallingParcelable(parcel)) {
        return false;
    }

    return true;
}

void Notification::ReadFromParcelBool(Parcel &parcel)
{
    // Read enableLight_
    enableLight_ = parcel.ReadBool();

    // Read enableSound_
    enableSound_ = parcel.ReadBool();

    // Read enableVibration_
    enableVibration_ = parcel.ReadBool();

    // Read isRemoveAllowed_
    isRemoveAllowed_ = parcel.ReadBool();

    // Read isPrivileged_
    isPrivileged_ = parcel.ReadBool();
}

void Notification::ReadFromParcelString(Parcel &parcel)
{
    // Read key_
    key_ = parcel.ReadString();

    // Read sound_
    if (enableSound_) {
        sound_ = std::make_shared<Uri>(parcel.ReadString());
    }

    // Read deviceId_
    deviceId_ = parcel.ReadString();
}

void Notification::ReadFromParcelInt32(Parcel &parcel)
{
    // Read ledLightColor_
    ledLightColor_ = parcel.ReadInt32();

    // Read lockscreenVisibleness_
    lockscreenVisibleness_ = static_cast<NotificationConstant::VisiblenessType>(parcel.ReadInt32());

    // Read remindType_
    remindType_ = static_cast<NotificationConstant::RemindType>(parcel.ReadInt32());

    // Read sourceType_
    sourceType_ = static_cast<NotificationConstant::SourceType>(parcel.ReadInt32());
}

void Notification::ReadFromParcelInt64(Parcel &parcel)
{
    // Read postTime_
    postTime_ = parcel.ReadInt64();

    // Read vibrationStyle_
    parcel.ReadInt64Vector(&vibrationStyle_);
}

void Notification::ReadFromParcelUint64(Parcel &parcel)
{
    updateTimerId_ = parcel.ReadUint64();
    finishTimerId_ = parcel.ReadUint64();
    archiveTimerId_ = parcel.ReadUint64();
}

bool Notification::ReadFromParcelParcelable(Parcel &parcel)
{
    // Read request_
    request_ = parcel.ReadStrongParcelable<NotificationRequest>();
    return request_ != nullptr;
}

bool Notification::ReadFromParcel(Parcel &parcel)
{
    ReadFromParcelBool(parcel);
    ReadFromParcelString(parcel);
    ReadFromParcelInt32(parcel);
    ReadFromParcelInt64(parcel);
    ReadFromParcelUint64(parcel);
    if (!ReadFromParcelParcelable(parcel)) {
        ANS_LOGE("ReadFromParcelParcelable from parcel error");
        return false;
    }

    return true;
}

Notification *Notification::Unmarshalling(Parcel &parcel)
{
    Notification *n = new (std::nothrow) Notification();
    if (n && !n->ReadFromParcel(parcel)) {
        ANS_LOGE("Read from parcel error");
        delete n;
        n = nullptr;
    }
    return n;
}

void Notification::SetEnableSound(const bool &enable)
{
    enableSound_ = enable;
}

void Notification::SetEnableLight(const bool &enable)
{
    enableLight_ = enable;
}

void Notification::SetEnableVibration(const bool &enable)
{
    enableVibration_ = enable;
}

void Notification::SetLedLightColor(const int32_t &color)
{
    ledLightColor_ = color;
}

void Notification::SetLockScreenVisbleness(const NotificationConstant::VisiblenessType &visbleness)
{
    lockscreenVisibleness_ = visbleness;
}

void Notification::SetPostTime(const int64_t &time)
{
    postTime_ = time;
}

void Notification::SetSound(const Uri &sound)
{
    sound_ = std::make_shared<Uri>(sound.ToString());
}

void Notification::SetVibrationStyle(const std::vector<int64_t> &style)
{
    vibrationStyle_ = style;
}

void Notification::SetRemindType(const NotificationConstant::RemindType &reminType)
{
    remindType_ = reminType;
}

void Notification::SetRemoveAllowed(bool removeAllowed)
{
    isRemoveAllowed_ = removeAllowed;
}

void Notification::SetPrivileged(const bool &isPrivileged)
{
    isPrivileged_ = isPrivileged;
}

void Notification::SetSourceType(NotificationConstant::SourceType sourceType)
{
    sourceType_ = sourceType;
}

std::string Notification::Dump() const
{
    std::string vibrationStyle = "";
    for (const auto &style : vibrationStyle_) {
        vibrationStyle += std::to_string(style);
        vibrationStyle += ", ";
    }
    return "Notification{ "
            "key = " + key_ +
            ", ledLightColor = " + std::to_string(ledLightColor_) +
            ", lockscreenVisbleness = " + std::to_string(static_cast<int32_t>(lockscreenVisibleness_)) +
            ", remindType = " + std::to_string(static_cast<int32_t>(remindType_)) +
            ", isRemoveAllowed = " + (isRemoveAllowed_ ? "true" : "false") +
            ", sourceType = " + std::to_string(static_cast<int32_t>(sourceType_)) +
            ", deviceId = " + deviceId_ +
            ", request = " + (request_ == nullptr ? "nullptr" : request_->Dump()) +
            ", postTime = " + std::to_string(postTime_) +
            ", sound = " + (sound_ == nullptr ? "nullptr" : sound_->ToString()) +
            ", vibrationStyle = [" + vibrationStyle + "]" +
            ", updateTimer = " + std::to_string(updateTimerId_) +
            ", finishTimer = " + std::to_string(finishTimerId_) +
            ", archiveTimer = " + std::to_string(archiveTimerId_) +
            ", isPrivileged = " + (isPrivileged_ ? "true" : "false") +
            " }";
}

uint64_t Notification::GetUpdateTimer() const
{
    return updateTimerId_;
}

void Notification::SetUpdateTimer(uint64_t updateTimerId)
{
    updateTimerId_ = updateTimerId;
}

uint64_t Notification::GetFinishTimer() const
{
    return finishTimerId_;
}

void Notification::SetFinishTimer(uint64_t finishTimerId)
{
    finishTimerId_ = finishTimerId;
}

void Notification::SetArchiveTimer(uint64_t archiveTimerId)
{
    archiveTimerId_ = archiveTimerId;
}

uint64_t Notification::GetArchiveTimer() const
{
    return archiveTimerId_;
}

void Notification::SetAutoDeletedTimer(uint64_t autoDeletedTimerId)
{
    autoDeletedTimerId_ = autoDeletedTimerId;
}

uint64_t Notification::GetAutoDeletedTimer() const
{
    return autoDeletedTimerId_;
}
}  // namespace Notification
}  // namespace OHOS
