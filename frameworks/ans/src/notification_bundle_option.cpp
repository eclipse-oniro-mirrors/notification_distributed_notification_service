/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "notification_bundle_option.h"

#include <string>                        // for operator+, basic_string, to_...

#include "ans_log_wrapper.h"
#include "parcel.h"                      // for Parcel

namespace OHOS {
namespace Notification {
NotificationBundleOption::NotificationBundleOption(const std::string &bundleName, const int32_t uid)
    : bundleName_(bundleName), uid_(uid)
{}

NotificationBundleOption::~NotificationBundleOption()
{}

void NotificationBundleOption::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

std::string NotificationBundleOption::GetBundleName() const
{
    return bundleName_;
}

void NotificationBundleOption::SetAppName(const std::string &appName)
{
    appName_ = appName;
}

std::string NotificationBundleOption::GetAppName() const
{
    return appName_;
}

void NotificationBundleOption::SetUid(const int32_t uid)
{
    uid_ = uid;
}

int32_t NotificationBundleOption::GetUid() const
{
    return uid_;
}

void NotificationBundleOption::SetInstanceKey(const int32_t key)
{
    instanceKey_ = key;
}

int32_t NotificationBundleOption::GetInstanceKey() const
{
    return instanceKey_;
}

void NotificationBundleOption::SetAppInstanceKey(const std::string &key)
{
    appInstanceKey_ = key;
}
 
std::string NotificationBundleOption::GetAppInstanceKey() const
{
    return appInstanceKey_;
}

void NotificationBundleOption::SetAppIndex(const int32_t appIndex)
{
    appIndex_ = appIndex;
}

int32_t NotificationBundleOption::GetAppIndex() const
{
    return appIndex_;
}

std::string NotificationBundleOption::Dump()
{
    return "NotificationBundleOption{ "
            "bundleName = " + bundleName_ +
            ", uid = " + std::to_string(uid_) +
            ", instanceKey = " + std::to_string(instanceKey_) +
            ", appIndex = " + std::to_string(appIndex_) +
            " }";
}

bool NotificationBundleOption::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName_)) {
        ANS_LOGE("Failed to write bundle name");
        return false;
    }

    if (!parcel.WriteString(appName_)) {
        ANS_LOGE("Failed to write app name");
        return false;
    }

    if (!parcel.WriteInt32(uid_)) {
        ANS_LOGE("Failed to write uid");
        return false;
    }

    if (!parcel.WriteInt32(instanceKey_)) {
        ANS_LOGE("Failed to write instance key");
        return false;
    }

    return true;
}

NotificationBundleOption *NotificationBundleOption::Unmarshalling(Parcel &parcel)
{
    auto pbundleOption = new (std::nothrow) NotificationBundleOption();
    if (pbundleOption && !pbundleOption->ReadFromParcel(parcel)) {
        delete pbundleOption;
        pbundleOption = nullptr;
    }

    return pbundleOption;
}

bool NotificationBundleOption::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(bundleName_)) {
        ANS_LOGE("Failed to read bundle name");
        return false;
    }

    if (!parcel.ReadString(appName_)) {
        ANS_LOGE("Failed to read app name");
        return false;
    }

    uid_ = parcel.ReadInt32();

    instanceKey_ = parcel.ReadInt32();

    return true;
}

bool NotificationBundleOption::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["uid"] = uid_;
    jsonObject["bundleName"] = bundleName_;
    jsonObject["instanceKey"] = instanceKey_;
    jsonObject["appIndex"] = appIndex_;
    return true;
}

NotificationBundleOption *NotificationBundleOption::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *pBundle = new (std::nothrow) NotificationBundleOption();
    if (pBundle == nullptr) {
        ANS_LOGE("null pBundle");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("uid") != jsonEnd && jsonObject.at("uid").is_number_integer()) {
        pBundle->uid_ = jsonObject.at("uid").get<int32_t>();
    }

    if (jsonObject.find("bundleName") != jsonEnd && jsonObject.at("bundleName").is_string()) {
        pBundle->bundleName_ = jsonObject.at("bundleName").get<std::string>();
    }

    if (jsonObject.find("instanceKey") != jsonEnd && jsonObject.at("instanceKey").is_number_integer()) {
        pBundle->instanceKey_ = jsonObject.at("instanceKey").get<int32_t>();
    }

    if (jsonObject.find("appIndex") != jsonEnd && jsonObject.at("appIndex").is_number_integer()) {
        pBundle->appIndex_ = jsonObject.at("appIndex").get<int32_t>();
    }
    return pBundle;
}

}  // namespace Notification
}  // namespace OHOS
