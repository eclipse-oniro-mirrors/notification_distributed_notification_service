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

#include <string>
#include "ans_log_wrapper.h"
#include "notification_extension_subscription_info.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
NotificationExtensionSubscriptionInfo::NotificationExtensionSubscriptionInfo(
    const std::string& addr, const NotificationConstant::SubscribeType type)
    : addr_(addr), type_(type)
{}

NotificationExtensionSubscriptionInfo::~NotificationExtensionSubscriptionInfo()
{}

std::string NotificationExtensionSubscriptionInfo::GetAddr() const
{
    return addr_;
}

void NotificationExtensionSubscriptionInfo::SetAddr(const std::string& addr)
{
    addr_ = addr;
}

bool NotificationExtensionSubscriptionInfo::IsHfp() const
{
    return isHfp_;
}

void NotificationExtensionSubscriptionInfo::SetHfp(const bool& hfp)
{
    isHfp_ = hfp;
}

NotificationConstant::SubscribeType NotificationExtensionSubscriptionInfo::GetType() const
{
    return type_;
}

void NotificationExtensionSubscriptionInfo::SetType(const NotificationConstant::SubscribeType type)
{
    type_ = type;
}

std::string NotificationExtensionSubscriptionInfo::Dump()
{
    return "NotificationExtensionSubscriptionInfo{ "
            "addr = " + addr_ +
            ", type = " + std::to_string(static_cast<int32_t>(type_)) +
            " }";
}

bool NotificationExtensionSubscriptionInfo::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteString(addr_)) {
        ANS_LOGE("Failed to write address");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ANS_LOGE("Failed to write type");
        return false;
    }

    return true;
}

NotificationExtensionSubscriptionInfo *NotificationExtensionSubscriptionInfo::Unmarshalling(Parcel& parcel)
{
    auto pNotificationExtensionSubscriptionInfo = new (std::nothrow) NotificationExtensionSubscriptionInfo();
    if (pNotificationExtensionSubscriptionInfo && !pNotificationExtensionSubscriptionInfo->ReadFromParcel(parcel)) {
        delete pNotificationExtensionSubscriptionInfo;
        pNotificationExtensionSubscriptionInfo = nullptr;
    }

    return pNotificationExtensionSubscriptionInfo;
}

bool NotificationExtensionSubscriptionInfo::ReadFromParcel(Parcel& parcel)
{
    if (!parcel.ReadString(addr_)) {
        ANS_LOGE("Failed to read address");
        return false;
    }

    type_ = static_cast<NotificationConstant::SubscribeType>(parcel.ReadInt32());

    return true;
}

bool NotificationExtensionSubscriptionInfo::ToJson(nlohmann::json& jsonObject) const
{
    jsonObject["addr"] = addr_;
    jsonObject["isHfp"] = isHfp_;
    jsonObject["type"] = static_cast<int32_t>(type_);

    return true;
}

NotificationExtensionSubscriptionInfo* NotificationExtensionSubscriptionInfo::FromJson(const nlohmann::json& jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *pDistributedBundleOption = new (std::nothrow) NotificationExtensionSubscriptionInfo();
    if (pDistributedBundleOption == nullptr) {
        ANS_LOGE("null pDistributedBundleOption");
        return nullptr;
    }

    const auto& jsonEnd = jsonObject.cend();

    if (jsonObject.find("addr") != jsonEnd && jsonObject.at("addr").is_string()) {
        pDistributedBundleOption->addr_ = jsonObject.at("addr").get<std::string>();
    }

    if (jsonObject.find("isHfp") != jsonEnd && jsonObject.at("isHfp").is_boolean()) {
        pDistributedBundleOption->isHfp_ = jsonObject.at("isHfp").get<bool>();
    }

    if (jsonObject.find("type") != jsonEnd && jsonObject.at("type").is_number_integer()) {
        auto typeValue  = jsonObject.at("type").get<int32_t>();
        pDistributedBundleOption->type_ = static_cast<NotificationConstant::SubscribeType>(typeValue);
    }

    return pDistributedBundleOption;
}

}  // namespace Notification
}  // namespace OHOS