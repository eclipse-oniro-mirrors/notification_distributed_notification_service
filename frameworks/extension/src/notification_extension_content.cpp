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

#include "notification_extension_content.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
void NotificationExtensionContent::SetTitle(const std::string& title)
{
    title_ = title;
}

std::string NotificationExtensionContent::GetTitle() const
{
    return title_;
}

void NotificationExtensionContent::SetText(const std::string& text)
{
    text_ = text;
}

std::string NotificationExtensionContent::GetText() const
{
    return text_;
}

std::string NotificationExtensionContent::Dump()
{
    return "title = " + title_ + ", text = " + text_;
}

bool NotificationExtensionContent::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["title"] = title_;
    jsonObject["text"] = text_;
    return true;
}

bool NotificationExtensionContent::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(title_)) {
        ANS_LOGE("Failed to write title");
        return false;
    }

    if (!parcel.WriteString(text_)) {
        ANS_LOGE("Failed to write text");
        return false;
    }

    return true;
}

NotificationExtensionContent *NotificationExtensionContent::Unmarshalling(Parcel &parcel)
{
    auto templ = new (std::nothrow) NotificationExtensionContent();
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

bool NotificationExtensionContent::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(title_)) {
        ANS_LOGE("Failed to read title");
        return false;
    }

    if (!parcel.ReadString(text_)) {
        ANS_LOGE("Failed to read text");
        return false;
    }

    return true;
}

NotificationExtensionContent *NotificationExtensionContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pInfo = new (std::nothrow) NotificationExtensionContent();
    if (pInfo == nullptr) {
        ANS_LOGE("null pInfo");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("title") != jsonEnd && jsonObject.at("title").is_string()) {
        pInfo->title_ = jsonObject.at("title").get<std::string>();
    }

    if (jsonObject.find("text") != jsonEnd && jsonObject.at("text").is_string()) {
        pInfo->text_ = jsonObject.at("text").get<std::string>();
    }

    return pInfo;
}
}  // namespace Notification
}  // namespace OHOS