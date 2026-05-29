/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "notification_subscribe_info.h"

#include <string>                         // for basic_string, operator+
#include <vector>                         // for vector

#include "ans_log_wrapper.h"
#include "parcel.h"                       // for Parcel
#include "refbase.h"
#include "voice_content_option.h"
#include "picture_option.h"

namespace OHOS {
namespace Notification {
constexpr uint32_t MAX_SLOT_SIZE = 1000;
NotificationSubscribeInfo::NotificationSubscribeInfo()
{}

NotificationSubscribeInfo::~NotificationSubscribeInfo()
{}

NotificationSubscribeInfo::NotificationSubscribeInfo(const NotificationSubscribeInfo &subscribeInfo)
{
    appNames_ = subscribeInfo.GetAppNames();
    appUids_ = subscribeInfo.GetAppUids();
    deviceType_ = subscribeInfo.GetDeviceType();
    userId_ = subscribeInfo.GetAppUserId();
    subscriberUid_ = subscribeInfo.GetSubscriberUid();
    slotTypes_ = subscribeInfo.GetSlotTypes();
    filterType_ = subscribeInfo.GetFilterType();
    voiceContentOption_ = subscribeInfo.GetVoiceContentOption();
    pictureOption_ = subscribeInfo.GetPictureOption();
}

void NotificationSubscribeInfo::AddAppName(const std::string appName)
{
    appNames_.push_back(appName);
}

void NotificationSubscribeInfo::AddAppNames(const std::vector<std::string> &appNames)
{
    appNames_.insert(appNames_.end(), appNames.begin(), appNames.end());
}

std::vector<std::string> NotificationSubscribeInfo::GetAppNames() const
{
    return appNames_;
}

void NotificationSubscribeInfo::AddAppUid(const int32_t appUid)
{
    appUids_.push_back(appUid);
}

void NotificationSubscribeInfo::AddAppUids(const std::vector<int32_t> &appUids)
{
    appUids_.insert(appUids_.end(), appUids.begin(), appUids.end());
}

std::vector<int32_t> NotificationSubscribeInfo::GetAppUids() const
{
    return appUids_;
}

void NotificationSubscribeInfo::AddAppUserId(const int32_t userId)
{
    userId_ = userId;
}

int32_t NotificationSubscribeInfo::GetAppUserId() const
{
    return userId_;
}

void NotificationSubscribeInfo::AddDeviceType(const std::string deviceType)
{
    deviceType_ = deviceType;
}

std::string NotificationSubscribeInfo::GetDeviceType() const
{
    return deviceType_;
}

bool NotificationSubscribeInfo::MarshallingVoiceContentOption(Parcel &parcel) const
{
    bool hasVoice = (voiceContentOption_ != nullptr);
    if (!parcel.WriteBool(hasVoice)) {
        ANS_LOGE("Can't write hasVoiceContentOption");
        return false;
    }
    if (hasVoice && !voiceContentOption_->Marshalling(parcel)) {
        ANS_LOGE("Can't write voiceContentOption_");
        return false;
    }
    return true;
}

bool NotificationSubscribeInfo::MarshallingPictureOption(Parcel &parcel) const
{
    bool hasPicture = (pictureOption_ != nullptr);
    if (!parcel.WriteBool(hasPicture)) {
        ANS_LOGE("Can't write hasPictureOption");
        return false;
    }
    if (hasPicture && !pictureOption_->Marshalling(parcel)) {
        ANS_LOGE("Can't write pictureOption_");
        return false;
    }
    return true;
}

bool NotificationSubscribeInfo::Marshalling(Parcel &parcel) const
{
    // write appNames_
    if (!parcel.WriteStringVector(appNames_)) {
        ANS_LOGE("Can't write appNames_");
        return false;
    }
    // write deviceType_
    if (!parcel.WriteString(deviceType_)) {
        ANS_LOGE("Can't write deviceType_");
        return false;
    }
    // write userId_
    if (!parcel.WriteInt32(userId_)) {
        ANS_LOGE("Can't write userId_");
        return false;
    }
     //write slotTypes_
    if (!parcel.WriteUint32(slotTypes_.size())) {
        ANS_LOGE("Failed to write slotTypes_ size.");
        return false;
    }
    for (auto slotType : slotTypes_) {
        if (!parcel.WriteInt32(static_cast<int32_t>(slotType))) {
            ANS_LOGE("Failed to write slotType");
            return false;
        }
    }
    // write filterType_
    if (!parcel.WriteUint32(filterType_)) {
        ANS_LOGE("Can't write filterType_");
        return false;
    }

    // write needNotifyApplicationChanged_
    if (!parcel.WriteBool(needNotifyApplicationChanged_)) {
        ANS_LOGE("Can't write needNotifyApplicationChanged");
        return false;
    }

    // write needNotifyResponse
    if (!parcel.WriteBool(needNotifyResponse_)) {
        ANS_LOGE("Can't write needNotifyResponse");
        return false;
    }

    // write isSubscribeSelf
    if (!parcel.WriteBool(isSubscribeSelf_)) {
        ANS_LOGE("Can't write isSubscribeSelf");
        return false;
    }
    if (!parcel.WriteUint32(subscribedFlags_)) {
        ANS_LOGE("Can't write subscribedFlags");
        return false;
    }
    if (!MarshallingVoiceContentOption(parcel)) {
        return false;
    }
    return MarshallingPictureOption(parcel);
}

NotificationSubscribeInfo *NotificationSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    NotificationSubscribeInfo *info = new (std::nothrow) NotificationSubscribeInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }

    return info;
}

void NotificationSubscribeInfo::SetSubscribedFlags(uint32_t subscribedFlags)
{
    subscribedFlags_ = subscribedFlags;
}

uint32_t NotificationSubscribeInfo::GetSubscribedFlags() const
{
    return subscribedFlags_;
}

bool NotificationSubscribeInfo::ReadVoiceContentOptionFromParcel(Parcel &parcel)
{
    bool hasVoiceContentOption = parcel.ReadBool();
    if (hasVoiceContentOption) {
        voiceContentOption_ = VoiceContentOption::Unmarshalling(parcel);
        if (voiceContentOption_ == nullptr) {
            ANS_LOGE("Failed to unmarshal voiceContentOption_");
            return false;
        }
    }
    return true;
}

bool NotificationSubscribeInfo::ReadPictureOptionFromParcel(Parcel &parcel)
{
    bool hasPictureOption = parcel.ReadBool();
    if (hasPictureOption) {
        pictureOption_ = PictureOption::Unmarshalling(parcel);
        if (pictureOption_ == nullptr) {
            ANS_LOGE("Failed to unmarshal pictureOption_");
            return false;
        }
    }
    return true;
}

bool NotificationSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&appNames_)) {
        ANS_LOGE("Can't read appNames_");
        return false;
    }
    if (!parcel.ReadString(deviceType_)) {
        ANS_LOGE("Can't read deviceType_");
        return false;
    }
    if (!parcel.ReadInt32(userId_)) {
        ANS_LOGE("Can't read userId_");
        return false;
    }
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ANS_LOGE("Can't read size");
        return false;
    }
    if (size > MAX_SLOT_SIZE) {
        ANS_LOGE("slotType_ size over 1000.");
        return false;
    }
    for (uint32_t index = 0; index < size; index++) {
        int32_t slotType = -1;
        if (!parcel.ReadInt32(slotType)) {
            ANS_LOGE("Can't read slotType");
            return false;
        }
        slotTypes_.emplace_back(static_cast<NotificationConstant::SlotType>(slotType));
    }
    if (!parcel.ReadUint32(filterType_)) {
        ANS_LOGE("Can't read filterType_");
        return false;
    }
    needNotifyApplicationChanged_ = parcel.ReadBool();
    needNotifyResponse_ = parcel.ReadBool();
    isSubscribeSelf_ = parcel.ReadBool();
    subscribedFlags_ = parcel.ReadUint32();
    if (!ReadVoiceContentOptionFromParcel(parcel)) {
        return false;
    }
    return ReadPictureOptionFromParcel(parcel);
}

std::string NotificationSubscribeInfo::Dump()
{
    std::string appNames = "";
    for (auto name : appNames_) {
        appNames += name;
        appNames += ", ";
    }
    std::string slotTypes = "";
    for (auto slotType : slotTypes_) {
        slotTypes += std::to_string(static_cast<int32_t>(slotType));
        slotTypes += ", ";
    }
    std::string voiceContentOption = "null";
    if (voiceContentOption_ != nullptr) {
        voiceContentOption = voiceContentOption_->GetEnabled() ? "enabled" : "disabled";
    }
    std::string pictureOption = "null";
    if (pictureOption_ != nullptr) {
        std::vector<std::string> picList = pictureOption_->GetPreparseLiveViewPicList();
        if (!picList.empty()) {
            pictureOption = "[";
            for (const auto &pic : picList) {
                pictureOption += pic + ", ";
            }
            pictureOption += "]";
        } else {
            pictureOption = "[]";
        }
    }
    return "NotificationSubscribeInfo{ "
            "appNames = [" + appNames + "]" +
            "deviceType = " + deviceType_ +
            "userId = " + std::to_string(userId_) +
            "slotTypes = [" + slotTypes + "]" +
            "needNotify = " + std::to_string(needNotifyApplicationChanged_) +
            "filterType = " + std::to_string(filterType_) +
            "needResponse = " + std::to_string(needNotifyResponse_) +
            "isSubscribeSelf = " + std::to_string(isSubscribeSelf_) +
            "voiceContentOption = " + voiceContentOption +
            "pictureOption = " + pictureOption +
            " }";
}

void NotificationSubscribeInfo::SetSubscriberUid(const int32_t uid)
{
    subscriberUid_ = uid;
}

int32_t NotificationSubscribeInfo::GetSubscriberUid() const
{
    return subscriberUid_;
}

void NotificationSubscribeInfo::SetSubscriberBundleName(const std::string &bundleName)
{
    subscriberBundleName_ = bundleName;
}

std::string NotificationSubscribeInfo::GetSubscriberBundleName() const
{
    return subscriberBundleName_;
}

void NotificationSubscribeInfo::SetSlotTypes(const std::vector<NotificationConstant::SlotType> slotTypes)
{
    slotTypes_ = slotTypes;
}

std::vector<NotificationConstant::SlotType> NotificationSubscribeInfo::GetSlotTypes() const
{
    return slotTypes_;
}

void NotificationSubscribeInfo::SetFilterType(const uint32_t filterType)
{
    filterType_ = filterType;
}

uint32_t NotificationSubscribeInfo::GetFilterType() const
{
    return filterType_;
}

bool NotificationSubscribeInfo::GetNeedNotifyApplication() const
{
    return needNotifyApplicationChanged_;
}

void NotificationSubscribeInfo::SetNeedNotifyApplication(bool isNeed)
{
    needNotifyApplicationChanged_ = isNeed;
}

bool NotificationSubscribeInfo::GetNeedNotifyResponse() const
{
    return needNotifyResponse_;
}

void NotificationSubscribeInfo::SetNeedNotifyResponse(bool isNeed)
{
    needNotifyResponse_ = isNeed;
}

bool NotificationSubscribeInfo::GetIsSubscribeSelf() const
{
    return isSubscribeSelf_;
}

void NotificationSubscribeInfo::SetIsSubscribeSelf(bool isSubscribeSelf)
{
    isSubscribeSelf_ = isSubscribeSelf;
}

void NotificationSubscribeInfo::SetVoiceContentOption(const sptr<VoiceContentOption> &option)
{
    voiceContentOption_ = option;
}

sptr<VoiceContentOption> NotificationSubscribeInfo::GetVoiceContentOption() const
{
    return voiceContentOption_;
}

void NotificationSubscribeInfo::SetPictureOption(const sptr<PictureOption> &option)
{
    pictureOption_ = option;
}

sptr<PictureOption> NotificationSubscribeInfo::GetPictureOption() const
{
    return pictureOption_;
}
}  // namespace Notification
}  // namespace OHOS
