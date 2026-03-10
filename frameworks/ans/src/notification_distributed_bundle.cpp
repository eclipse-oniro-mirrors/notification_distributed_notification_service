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

#include "notification_distributed_bundle.h"

#include <string>
#include "ans_log_wrapper.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {

NotificationDistributedBundle::NotificationDistributedBundle(std::string bundleName, int32_t uid)
    : uid_(uid), bundleName_(bundleName)
{}

int32_t NotificationDistributedBundle::GetBundleUid() const
{
    return uid_;
}

void NotificationDistributedBundle::SetBundleUid(int32_t uid)
{
    uid_ = uid;
}

std::string NotificationDistributedBundle::GetBundleName() const
{
    return bundleName_;
}

void NotificationDistributedBundle::SetBundleName(const std::string& name)
{
    bundleName_ = name;
}

std::string NotificationDistributedBundle::GetBundleLabel() const
{
    return appLabel_;
}

void NotificationDistributedBundle::SetBundleLabel(const std::string& label)
{
    appLabel_ = label;
}

std::shared_ptr<Media::PixelMap> NotificationDistributedBundle::GetBundleIcon() const
{
    return icon_;
}

void NotificationDistributedBundle::SetBundleIcon(const std::shared_ptr<Media::PixelMap> icon)
{
    icon_ = icon;
}

bool NotificationDistributedBundle::IsAncoBundle() const
{
    return isAnco_;
}

void NotificationDistributedBundle::SetAncoBundle(bool isAnco)
{
    isAnco_ = isAnco;
}

int32_t NotificationDistributedBundle::GetAppIndex() const
{
    return appIndex_;
}

void NotificationDistributedBundle::SetAppIndex(const int32_t appIndex)
{
    appIndex_ = appIndex;
}

void NotificationDistributedBundle::SetInstalledbundle(const std::string& bundleName,
    const std::string& label)
{
    if (bundleName.empty() && label.empty()) {
        existSame_ = false;
    } else {
        existSame_ = true;
    }
    installedAppLabel_ = label;
    installedBundleName_ = bundleName;
}

bool NotificationDistributedBundle::CheckInstalledBundle(const std::string bundleName,
    const std::string label) const
{
    if (!installedAppLabel_.empty() && installedAppLabel_ == label) {
        return true;
    }

    if (!installedBundleName_.empty() && installedBundleName_ == bundleName) {
        return true;
    }
    return false;
}

bool NotificationDistributedBundle::CheckSameBundle() const
{
    return !installedBundleName_.empty() || !installedAppLabel_.empty();
}

NotificationConstant::SWITCH_STATE NotificationDistributedBundle::GetLiveViewEnable() const
{
    return liveView_;
}

void NotificationDistributedBundle::SetLiveViewEnable(NotificationConstant::SWITCH_STATE enable)
{
    liveView_ = enable;
}

NotificationConstant::SWITCH_STATE NotificationDistributedBundle::GetNotificationEnable() const
{
    return notification_;
}

void NotificationDistributedBundle::SetNotificationEnable(NotificationConstant::SWITCH_STATE enable)
{
    notification_ = enable;
}

std::string NotificationDistributedBundle::Dump() const
{
    return "NotificationDistributedBundle{ name = " + bundleName_ + ", uid = " + std::to_string(uid_) +
        ", anco: " + std::to_string(isAnco_) + ", enable = " + std::to_string(static_cast<int32_t>(liveView_)) + " " +
        std::to_string(static_cast<int32_t>(notification_)) + ", icon = " + ((icon_ == nullptr) ? "null" : "not null") +
        ", same: " + std::to_string(existSame_) + ", index: " + std::to_string(appIndex_) + " }";
}

bool NotificationDistributedBundle::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isAnco_)) {
        ANS_LOGE("Failed to write anco");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(liveView_))) {
        ANS_LOGE("Failed to write liveview");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(notification_))) {
        ANS_LOGE("Failed to write notification");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    if (!parcel.WriteInt32(appIndex_)) {
        ANS_LOGE("Failed to write index");
        return false;
    }

    if (!parcel.WriteString(appLabel_)) {
        ANS_LOGE("Failed to write label");
        return false;
    }

    if (!parcel.WriteString(bundleName_)) {
        ANS_LOGE("Failed to write name");
        return false;
    }

    bool valid = icon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(icon_.get())) {
            ANS_LOGE("Failed to write bigIcon");
            return false;
        }
    }

    return true;
}

bool NotificationDistributedBundle::ReadFromParcel(Parcel &parcel)
{
    isAnco_ = parcel.ReadBool();
    int32_t liveViewType = parcel.ReadInt32();
    if (liveViewType < static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF) ||
        liveViewType > static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON)) {
        ANS_LOGE("Failed to read live type %{public}d", liveViewType);
        return false;
    }
    liveView_ = static_cast<NotificationConstant::SWITCH_STATE>(liveViewType);

    int32_t notificationType = parcel.ReadInt32();
    if (notificationType < static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF) ||
        notificationType > static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON)) {
        ANS_LOGE("Failed to read notification type %{public}d", notificationType);
        return false;
    }
    notification_ = static_cast<NotificationConstant::SWITCH_STATE>(notificationType);
    uid_ = parcel.ReadInt32();
    appIndex_ = parcel.ReadInt32();
    appLabel_ = parcel.ReadString();
    bundleName_ = parcel.ReadString();
    bool valid = parcel.ReadBool();
    if (valid) {
        icon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!icon_) {
            ANS_LOGE("bundle icon error");
            return false;
        }
    }

    return true;
}

NotificationDistributedBundle *NotificationDistributedBundle::Unmarshalling(Parcel &parcel)
{
    auto bundleInfo = new (std::nothrow) NotificationDistributedBundle();
    if (bundleInfo && !bundleInfo->ReadFromParcel(parcel)) {
        delete bundleInfo;
        bundleInfo = nullptr;
    }

    return bundleInfo;
}
}  // namespace Notification
}  // namespace OHOS
