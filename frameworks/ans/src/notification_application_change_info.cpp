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

#include "notification_application_change_info.h"

#include "ans_log_wrapper.h"
#include "parcel.h"                               // for Parcel

namespace OHOS {
namespace Notification {

void NotificationApplicationChangeInfo::SetChangeType(const DistributedBundleChangeType type)
{
    changeType_ = type;
}


DistributedBundleChangeType NotificationApplicationChangeInfo::GetChangeType() const
{
    return changeType_;
}

void NotificationApplicationChangeInfo::SetBundle(const std::shared_ptr<NotificationBundleOption> bundle)
{
    bundleOption_ = bundle;
}

std::shared_ptr<NotificationBundleOption> NotificationApplicationChangeInfo::GetBundle() const
{
    return bundleOption_;
}

void NotificationApplicationChangeInfo::SetEnable(const bool enable)
{
    switchEnable_ = enable;
}

bool NotificationApplicationChangeInfo::GetEnable() const
{
    return switchEnable_;
}

std::string NotificationApplicationChangeInfo::Dump()
{
    std::string bundleInfo = std::string();
    if (bundleOption_ != nullptr) {
        bundleInfo = bundleOption_->Dump();
    }
    return "ApplicationChangeInfo{ bundle = " + bundleInfo + ", type = " +
        std::to_string(changeType_) + ", enabel = " + std::to_string(switchEnable_) + " }";
}

bool NotificationApplicationChangeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(changeType_))) {
        ANS_LOGE("Failed to write changeType");
        return false;
    }

    if (!parcel.WriteBool(switchEnable_)) {
        ANS_LOGE("Failed to write enable");
        return false;
    }

    bool valid = (bundleOption_ == nullptr) ? false : true;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the bundle flag");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(bundleOption_.get())) {
            ANS_LOGE("Failed to write bundle");
            return false;
        }
    }

    return true;
}

bool NotificationApplicationChangeInfo::ReadFromParcel(Parcel &parcel)
{
    int32_t type = parcel.ReadInt32();
    if (type < static_cast<int32_t>(DistributedBundleChangeType::INIT_DEVICE_CONNECT) ||
        type > static_cast<int32_t>(DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE)) {
        ANS_LOGE("Failed to read type %{public}d", type);
        return false;
    }
    changeType_ = static_cast<DistributedBundleChangeType>(type);
    switchEnable_ = parcel.ReadBool();
    bool valid = parcel.ReadBool();
    if (valid) {
        bundleOption_ = std::shared_ptr<NotificationBundleOption>(parcel.ReadParcelable<NotificationBundleOption>());
        if (bundleOption_ == nullptr) {
            ANS_LOGE("Failed to read bundle");
            return false;
        }
    }

    return true;
}

NotificationApplicationChangeInfo *NotificationApplicationChangeInfo::Unmarshalling(Parcel &parcel)
{
    auto changeInfo = new (std::nothrow) NotificationApplicationChangeInfo();
    if (changeInfo != nullptr && !changeInfo->ReadFromParcel(parcel)) {
        delete changeInfo;
        changeInfo = nullptr;
    }

    return changeInfo;
}

}  // namespace Notification
}  // namespace OHOS
