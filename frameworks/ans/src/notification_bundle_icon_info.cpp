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

#include "notification_bundle_icon_info.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
NotificationBundleIconInfo::NotificationBundleIconInfo(
    const std::string &bundleName, const int32_t uid, const int32_t appIndex,
    const std::shared_ptr<Media::PixelMap> &icon)
    : bundleName_(bundleName), uid_(uid), appIndex_(appIndex), icon_(icon)
{}

NotificationBundleIconInfo::~NotificationBundleIconInfo()
{}

void NotificationBundleIconInfo::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

std::string NotificationBundleIconInfo::GetBundleName() const
{
    return bundleName_;
}

void NotificationBundleIconInfo::SetUid(const int32_t uid)
{
    uid_ = uid;
}

int32_t NotificationBundleIconInfo::GetUid() const
{
    return uid_;
}

void NotificationBundleIconInfo::SetAppIndex(const int32_t appIndex)
{
    appIndex_ = appIndex;
}

int32_t NotificationBundleIconInfo::GetAppIndex() const
{
    return appIndex_;
}

void NotificationBundleIconInfo::SetIcon(const std::shared_ptr<Media::PixelMap> &icon)
{
    icon_ = icon;
}

std::shared_ptr<Media::PixelMap> NotificationBundleIconInfo::GetIcon() const
{
    return icon_;
}

std::string NotificationBundleIconInfo::Dump()
{
    return "NotificationBundleIconInfo{ bundleName = " + bundleName_ +
           ", uid = " + std::to_string(uid_) +
           ", appIndex = " + std::to_string(appIndex_) +
           ", hasIcon = " + (icon_ ? "true" : "false") +
           " }";
}

bool NotificationBundleIconInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName_)) {
        ANS_LOGE("Failed to write bundle name");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    if (!parcel.WriteInt32(appIndex_)) {
        ANS_LOGE("Failed to write app index");
        return false;
    }

    bool valid = icon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether icon is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(icon_.get())) {
            ANS_LOGE("Failed to write icon");
            return false;
        }
    }

    return true;
}

NotificationBundleIconInfo *NotificationBundleIconInfo::Unmarshalling(Parcel &parcel)
{
    auto pNotificationBundleIconInfo = new (std::nothrow) NotificationBundleIconInfo();
    if (pNotificationBundleIconInfo && !pNotificationBundleIconInfo->ReadFromParcel(parcel)) {
        delete pNotificationBundleIconInfo;
        pNotificationBundleIconInfo = nullptr;
    }

    return pNotificationBundleIconInfo;
}

bool NotificationBundleIconInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(bundleName_)) {
        ANS_LOGE("Failed to read bundle name");
        return false;
    }

    uid_ = parcel.ReadInt32();

    appIndex_ = parcel.ReadInt32();

    bool valid = parcel.ReadBool();
    if (valid) {
        icon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!icon_) {
            ANS_LOGE("null icon");
            return false;
        }
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS
