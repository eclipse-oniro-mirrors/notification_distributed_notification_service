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
    if (other.request_ != nullptr) {
        request_ = new (std::nothrow) NotificationRequest(*(other.request_));
    }
    postTime_ = other.postTime_;
    sound_ = other.sound_;
    vibrationStyle_ = other.vibrationStyle_;
    isRemoveAllowed_ = other.isRemoveAllowed_;
    sourceType_ = other.sourceType_;
    deviceId_ = other.deviceId_;
    updateTimerId_ = other.updateTimerId_;
    finishTimerId_ = other.finishTimerId_;
    archiveTimerId_ = other.archiveTimerId_;
    if (other.voiceContent_ != nullptr) {
        voiceContent_ = std::make_shared<NotificationVoiceContent>(*other.voiceContent_);
    }
    if (other.notificationClassification_ != nullptr) {
        notificationClassification_ = new (std::nothrow) NotificationClassification(
            *other.notificationClassification_);
    }
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

    return true;
}

bool Notification::MarshallingString(Parcel &parcel) const
{
    if (!parcel.WriteString(key_)) {
        ANS_LOGE("Can't write key");
        return false;
    }

    if (enableSound_) {
        std::string soundStr = (sound_ != nullptr) ? sound_->ToString() : "";
        if (!parcel.WriteString(soundStr)) {
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
    int32_t visibleness = static_cast<int32_t>(lockscreenVisibleness_);
    if (visibleness < static_cast<int32_t>(NotificationConstant::VisiblenessType::NO_OVERRIDE) ||
        visibleness >= static_cast<int32_t>(NotificationConstant::VisiblenessType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid visibleness: %{public}d", visibleness);
        return false;
    }
    int32_t remindType = static_cast<int32_t>(remindType_);
    if (remindType < static_cast<int32_t>(NotificationConstant::RemindType::NONE) ||
        remindType > static_cast<int32_t>(NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND)) {
        ANS_LOGE("Invalid remind type: %{public}d", remindType);
        return false;
    }
    int32_t sourceType = static_cast<int32_t>(sourceType_);
    if (sourceType < static_cast<int32_t>(NotificationConstant::SourceType::TYPE_NORMAL) ||
        sourceType > static_cast<int32_t>(NotificationConstant::SourceType::TYPE_TIMER)) {
        ANS_LOGE("Invalid source type: %{public}d", sourceType);
        return false;
    }

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

    bool hasVoiceContent = (voiceContent_ != nullptr);
    if (!parcel.WriteBool(hasVoiceContent)) {
        ANS_LOGE("Failed to write hasVoiceContent");
        return false;
    }

    if (hasVoiceContent) {
        if (!parcel.WriteParcelable(voiceContent_.get())) {
            ANS_LOGE("Failed to write voiceContent");
            return false;
        }
    }

    bool hasNotificationClassification = (notificationClassification_ != nullptr);
    if (!parcel.WriteBool(hasNotificationClassification)) {
        ANS_LOGE("Failed to write hasNotificationClassification");
        return false;
    }

    if (hasNotificationClassification && !parcel.WriteStrongParcelable(notificationClassification_)) {
        ANS_LOGE("Failed to write notificationClassification");
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

bool Notification::ReadFromParcelBool(Parcel &parcel)
{
    if (!parcel.ReadBool(enableLight_)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    if (!parcel.ReadBool(enableSound_)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    if (!parcel.ReadBool(enableVibration_)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    if (!parcel.ReadBool(isRemoveAllowed_)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    return true;
}

bool Notification::ReadFromParcelString(Parcel &parcel)
{
    std::string key;
    if (!parcel.ReadString(key)) {
        ANS_LOGE("ReadString failed");
        return false;
    }
    key_ = key;

    if (enableSound_) {
        std::string soundStr;
        if (!parcel.ReadString(soundStr)) {
            ANS_LOGE("ReadString failed");
            return false;
        }
        sound_ = std::make_shared<Uri>(soundStr);
    }

    std::string deviceId;
    if (!parcel.ReadString(deviceId)) {
        ANS_LOGE("ReadString failed");
        return false;
    }
    deviceId_ = deviceId;
    return true;
}

bool Notification::ReadFromParcelInt32(Parcel &parcel)
{
    if (!parcel.ReadInt32(ledLightColor_)) {
        ANS_LOGE("ReadInt32 failed");
        return false;
    }

    int32_t visibleness = 0;
    if (!parcel.ReadInt32(visibleness)) {
        ANS_LOGE("ReadInt32 failed");
        return false;
    }
    if (visibleness < static_cast<int32_t>(NotificationConstant::VisiblenessType::NO_OVERRIDE) ||
        visibleness >= static_cast<int32_t>(NotificationConstant::VisiblenessType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid visibleness: %{public}d", visibleness);
        return false;
    }
    lockscreenVisibleness_ = static_cast<NotificationConstant::VisiblenessType>(visibleness);

    int32_t remindType = 0;
    if (!parcel.ReadInt32(remindType)) {
        ANS_LOGE("ReadInt32 failed");
        return false;
    }
    if (remindType < static_cast<int32_t>(NotificationConstant::RemindType::NONE) ||
        remindType > static_cast<int32_t>(NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND)) {
        ANS_LOGE("Invalid remind type: %{public}d", remindType);
        return false;
    }
    remindType_ = static_cast<NotificationConstant::RemindType>(remindType);

    int32_t sourceType = 0;
    if (!parcel.ReadInt32(sourceType)) {
        ANS_LOGE("ReadInt32 failed");
        return false;
    }
    if (sourceType < static_cast<int32_t>(NotificationConstant::SourceType::TYPE_NORMAL) ||
        sourceType > static_cast<int32_t>(NotificationConstant::SourceType::TYPE_TIMER)) {
        ANS_LOGE("Invalid source type: %{public}d", sourceType);
        return false;
    }
    sourceType_ = static_cast<NotificationConstant::SourceType>(sourceType);
    return true;
}

bool Notification::ReadFromParcelInt64(Parcel &parcel)
{
    if (!parcel.ReadInt64(postTime_)) {
        ANS_LOGE("ReadInt64 failed");
        return false;
    }
    if (!parcel.ReadInt64Vector(&vibrationStyle_)) {
        ANS_LOGE("ReadInt64Vector failed");
        return false;
    }
    return true;
}

bool Notification::ReadFromParcelUint64(Parcel &parcel)
{
    if (!parcel.ReadUint64(updateTimerId_)) {
        ANS_LOGE("ReadUint64 failed");
        return false;
    }
    if (!parcel.ReadUint64(finishTimerId_)) {
        ANS_LOGE("ReadUint64 failed");
        return false;
    }
    if (!parcel.ReadUint64(archiveTimerId_)) {
        ANS_LOGE("ReadUint64 failed");
        return false;
    }
    return true;
}

bool Notification::ReadFromParcelParcelable(Parcel &parcel)
{
    // Read request_
    request_ = parcel.ReadStrongParcelable<NotificationRequest>();
    if (request_ == nullptr) {
        return false;
    }

    // Read voiceContent_
    bool hasVoiceContent = false;
    if (!parcel.ReadBool(hasVoiceContent)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    if (hasVoiceContent) {
        voiceContent_ = std::shared_ptr<NotificationVoiceContent>(parcel.ReadParcelable<NotificationVoiceContent>());
        if (voiceContent_ == nullptr) {
            ANS_LOGE("Voice content read parcel error.");
            return false;
        }
    }

    bool hasNotificationClassification = false;
    if (!parcel.ReadBool(hasNotificationClassification)) {
        ANS_LOGE("ReadBool failed");
        return false;
    }
    if (hasNotificationClassification) {
        notificationClassification_ = parcel.ReadStrongParcelable<NotificationClassification>();
        if (notificationClassification_ == nullptr) {
            ANS_LOGE("Notification classification read parcel error.");
            return false;
        }
    }
    return true;
}

bool Notification::ReadFromParcel(Parcel &parcel)
{
    if (!ReadFromParcelBool(parcel)) {
        ANS_LOGE("ReadFromParcelBool from parcel error");
        return false;
    }
    if (!ReadFromParcelString(parcel)) {
        ANS_LOGE("ReadFromParcelString from parcel error");
        return false;
    }
    if (!ReadFromParcelInt32(parcel)) {
        ANS_LOGE("ReadFromParcelInt32 from parcel error");
        return false;
    }
    if (!ReadFromParcelInt64(parcel)) {
        ANS_LOGE("ReadFromParcelInt64 from parcel error");
        return false;
    }
    if (!ReadFromParcelUint64(parcel)) {
        ANS_LOGE("ReadFromParcelUint64 from parcel error");
        return false;
    }
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
    int32_t type = static_cast<int32_t>(visbleness);
    if (type < static_cast<int32_t>(NotificationConstant::VisiblenessType::NO_OVERRIDE) ||
        type >= static_cast<int32_t>(NotificationConstant::VisiblenessType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid visibleness: %{public}d", type);
        return;
    }
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

void Notification::SetSourceType(NotificationConstant::SourceType sourceType)
{
    int32_t type = static_cast<int32_t>(sourceType);
    if (type < static_cast<int32_t>(NotificationConstant::SourceType::TYPE_NORMAL) ||
        type > static_cast<int32_t>(NotificationConstant::SourceType::TYPE_TIMER)) {
        ANS_LOGE("Invalid source type: %{public}d", type);
        return;
    }
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
            ", notificationClassification = " +
            (notificationClassification_ == nullptr ? "nullptr" : notificationClassification_->Dump()) +
            ", updateTimer = " + std::to_string(updateTimerId_) +
            ", finishTimer = " + std::to_string(finishTimerId_) +
            ", archiveTimer = " + std::to_string(archiveTimerId_) +
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

uint64_t Notification::GetGeofenceTriggerTimer() const
{
    return triggerTimerId_;
}

void Notification::SetGeofenceTriggerTimer(uint64_t triggerTimerId)
{
    triggerTimerId_ = triggerTimerId;
}

void Notification::SetArchiveTimer(uint64_t archiveTimerId)
{
    archiveTimerId_ = archiveTimerId;
}

uint64_t Notification::GetArchiveTimer() const
{
    return archiveTimerId_;
}

void Notification::SetVoiceContent(const std::shared_ptr<NotificationVoiceContent> &voiceContent)
{
    voiceContent_ = voiceContent;
}

std::shared_ptr<NotificationVoiceContent> Notification::GetVoiceContent() const
{
    return voiceContent_;
}

void Notification::SetNotificationClassification(
    const sptr<NotificationClassification> &notificationClassification)
{
    notificationClassification_ = notificationClassification;
}

sptr<NotificationClassification> Notification::GetNotificationClassification() const
{
    return notificationClassification_;
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
