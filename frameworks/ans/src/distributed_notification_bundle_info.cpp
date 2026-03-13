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

#include "distributed_notification_bundle_info.h"
#include <string>
#include "ans_log_wrapper.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
DistributedNotificationBundleInfo::DistributedNotificationBundleInfo(const std::string& bundleName, const int32_t& uid)
    : uid_(uid), bundleName_(bundleName)
{}

DistributedNotificationBundleInfo::~DistributedNotificationBundleInfo()
{}

std::string DistributedNotificationBundleInfo::GetBundleName() const
{
    return bundleName_;
}

void DistributedNotificationBundleInfo::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

int32_t DistributedNotificationBundleInfo::GetBundleUid() const
{
    return uid_;
}

void DistributedNotificationBundleInfo::SetBundleUid(const int32_t uid)
{
    uid_ = uid;
}

const std::shared_ptr<AAFwk::WantParams> DistributedNotificationBundleInfo::GetExtendInfo() const
{
    return extendInfo_;
}

void DistributedNotificationBundleInfo::SetExtendInfo(const std::shared_ptr<AAFwk::WantParams> &extendInfo)
{
    extendInfo_ = extendInfo;
}

const std::shared_ptr<Media::PixelMap> DistributedNotificationBundleInfo::GetBundleIcon() const
{
    return icon_;
}

void DistributedNotificationBundleInfo::SetBundleIcon(const std::shared_ptr<Media::PixelMap> &icon)
{
    icon_ = icon;
}

bool DistributedNotificationBundleInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName_)) {
        ANS_LOGE("Failed to write bundle name");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    bool valid = icon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the icon flag.");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(icon_.get())) {
            ANS_LOGE("Failed to write icon");
            return false;
        }
    }

    valid = extendInfo_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the extend flag.");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(extendInfo_.get())) {
            ANS_LOGE("Failed to write extendInfo");
            return false;
        }
    }

    return true;
}

DistributedNotificationBundleInfo *DistributedNotificationBundleInfo::Unmarshalling(Parcel &parcel)
{
    auto pDistributedBundleInfo = new (std::nothrow) DistributedNotificationBundleInfo();
    if (pDistributedBundleInfo && !pDistributedBundleInfo->ReadFromParcel(parcel)) {
        delete pDistributedBundleInfo;
        pDistributedBundleInfo = nullptr;
    }

    return pDistributedBundleInfo;
}

bool DistributedNotificationBundleInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(bundleName_)) {
        ANS_LOGE("Failed to read bundle name");
        return false;
    }

    uid_ = parcel.ReadInt32();
    bool valid = parcel.ReadBool();
    if (valid) {
        icon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!icon_) {
            ANS_LOGE("null icon");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        extendInfo_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
        if (!extendInfo_) {
            ANS_LOGE("null extendInfo");
            return false;
        }
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
