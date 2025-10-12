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

#include "notification_info.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
void NotificationInfo::SetHashCode(const std::string& hashCode)
{
    hashCode_ = hashCode;
}

std::string NotificationInfo::GetHashCode() const
{
    return hashCode_;
}

void NotificationInfo::SetNotificationSlotType(NotificationConstant::SlotType notificationSlotType)
{
    notificationSlotType_ = notificationSlotType;
}

NotificationConstant::SlotType NotificationInfo::GetNotificationSlotType() const
{
    return notificationSlotType_;
}

void NotificationInfo::SetNotificationExtensionContent(std::shared_ptr<NotificationExtensionContent> content)
{
    content_ =  content;
}

std::shared_ptr<NotificationExtensionContent> NotificationInfo::GetNotificationExtensionContent() const
{
    return content_;
}

void NotificationInfo::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

std::string NotificationInfo::GetBundleName() const
{
    return bundleName_;
}

void NotificationInfo::SetDeliveryTime(int64_t deliveryTime)
{
    deliveryTime_ = deliveryTime;
}

int64_t NotificationInfo::GetDeliveryTime() const
{
    return deliveryTime_;
}

void NotificationInfo::SetGroupName(const std::string& groupName)
{
    groupName_ = groupName;
}

std::string NotificationInfo::GetGroupName() const
{
    return groupName_;
}

void NotificationInfo::SetAppName(const std::string& appName)
{
    appName_ = appName;
}

std::string NotificationInfo::GetAppName() const
{
    return appName_;
}

std::string NotificationInfo::Dump()
{
    return "hashCode = " + hashCode_ +
    ", notificationSlotType = " + std::to_string(static_cast<int64_t>(notificationSlotType_)) +
    ", NotificationExtensionContent { title = " + (content_ ? content_->GetTitle() : "null") +
    ", text = " + (content_ ? content_->GetText() : "null") +
    " }, bundleName = " + bundleName_ +
    ", deliveryTime = " + std::to_string(static_cast<int64_t>(deliveryTime_)) +
    ", groupName = " + groupName_ +
    ", appName = " + appName_;
}

bool NotificationInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["hashCode"] = hashCode_;
    jsonObject["notificationSlotType"] = static_cast<int32_t>(notificationSlotType_);

    if (content_ != nullptr) {
        nlohmann::json contentOptionObj;
        if (!NotificationJsonConverter::ConvertToJson(content_.get(), contentOptionObj)) {
            ANS_LOGE("Cannot convert notificationExtensionContent to JSON.");
            return false;
        }
        jsonObject["content"] = contentOptionObj;
    }

    jsonObject["bundleName"] = bundleName_;
    jsonObject["deliveryTime"] = deliveryTime_;
    jsonObject["groupName"] = groupName_;
    jsonObject["appName"] = appName_;

    return true;
}

bool NotificationInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(hashCode_)) {
        ANS_LOGE("Failed to write hashCode");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(notificationSlotType_))) {
        ANS_LOGE("Failed to write notificationSlotType");
        return false;
    }

    if (!parcel.WriteParcelable(content_.get())) {
        ANS_LOGE("Failed to write content");
        return false;
    }

    if (!parcel.WriteString(bundleName_)) {
        ANS_LOGE("Failed to write bundleName");
        return false;
    }

    if (!parcel.WriteInt64(deliveryTime_)) {
        ANS_LOGE("Failed to write deliveryTime");
        return false;
    }

    if (!parcel.WriteString(groupName_)) {
        ANS_LOGE("Failed to write groupName");
        return false;
    }

    if (!parcel.WriteString(appName_)) {
        ANS_LOGE("Failed to write appName");
        return false;
    }

    return true;
}

NotificationInfo *NotificationInfo::Unmarshalling(Parcel &parcel)
{
    auto templ = new (std::nothrow) NotificationInfo();
    if (templ == nullptr) {
        ANS_LOGE("null templ");
        return nullptr;
    }
    if (!templ->ReadFromParcel(parcel)) {
        delete templ;
        templ = nullptr;
    }

    return templ;
}

bool NotificationInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(hashCode_)) {
        ANS_LOGE("Failed to read hashCode");
        return false;
    }
    notificationSlotType_ = static_cast<NotificationConstant::SlotType>(parcel.ReadInt32());

    content_ = std::shared_ptr<NotificationExtensionContent>(parcel.ReadParcelable<NotificationExtensionContent>());
    if (!content_) {
        ANS_LOGE("Failed to read content");
        return false;
    }

    bundleName_ = parcel.ReadString();
    deliveryTime_ = parcel.ReadInt64();
    groupName_ = parcel.ReadString();
    appName_ = parcel.ReadString();

    return true;
}

NotificationInfo *NotificationInfo::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pInfo = new (std::nothrow) NotificationInfo();
    if (pInfo == nullptr) {
        ANS_LOGE("null pInfo");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("hashCode") != jsonEnd && jsonObject.at("hashCode").is_string()) {
        pInfo->hashCode_ = jsonObject.at("hashCode").get<std::string>();
    }

    if (jsonObject.find("notificationSlotType") != jsonEnd &&
        jsonObject.at("notificationSlotType").is_number_integer()) {
        auto notificationSlotType  = jsonObject.at("notificationSlotType").get<int32_t>();
        pInfo->notificationSlotType_ = static_cast<NotificationConstant::SlotType>(notificationSlotType);
    }

    if (jsonObject.find("content") != jsonEnd) {
        auto contentOptionObj = jsonObject.at("content");
        if (!contentOptionObj.is_null()) {
            auto *pExtensionContent =
                NotificationJsonConverter::ConvertFromJson<NotificationExtensionContent>(contentOptionObj);
            if (pExtensionContent == nullptr) {
                ANS_LOGE("null pExtensionContent");
                return nullptr;
            }

            pInfo->content_ = std::shared_ptr<NotificationExtensionContent>(pExtensionContent);
        }
    }

    if (jsonObject.find("bundleName") != jsonEnd && jsonObject.at("bundleName").is_string()) {
        pInfo->bundleName_ = jsonObject.at("bundleName").get<std::string>();
    }

    if (jsonObject.find("deliveryTime") != jsonEnd && jsonObject.at("deliveryTime").is_number_integer()) {
        pInfo->deliveryTime_ = jsonObject.at("deliveryTime").get<int64_t>();
    }

    if (jsonObject.find("groupName") != jsonEnd && jsonObject.at("groupName").is_string()) {
        pInfo->groupName_ = jsonObject.at("groupName").get<std::string>();
    }

    if (jsonObject.find("appName") != jsonEnd && jsonObject.at("appName").is_string()) {
        pInfo->appName_ = jsonObject.at("appName").get<std::string>();
    }

    return pInfo;
}
}  // namespace Notification
}  // namespace OHOS