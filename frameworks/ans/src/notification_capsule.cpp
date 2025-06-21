/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "notification_capsule.h"

#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type


#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel
#include "pixel_map.h"        // for PixelMap

namespace OHOS {
namespace Notification {

void NotificationCapsule::SetTitle(const std::string &title)
{
    title_ = title;
}

std::string NotificationCapsule::GetTitle() const
{
    return title_;
}

void NotificationCapsule::SetBackgroundColor(const std::string &color)
{
    backgroundColor_ = color;
}

std::string NotificationCapsule::GetBackgroundColor() const
{
    return backgroundColor_;
}

void NotificationCapsule::SetIcon(const std::shared_ptr<Media::PixelMap> &pixelMap)
{
    icon_ = pixelMap;
}

const std::shared_ptr<Media::PixelMap> NotificationCapsule::GetIcon() const
{
    return icon_;
}

void NotificationCapsule::SetContent(const std::string &content)
{
    content_ = content;
}

std::string NotificationCapsule::GetContent() const
{
    return content_;
}

std::vector<NotificationIconButton> NotificationCapsule::GetCapsuleButton() const
{
    return capsuleButton_;
}

void NotificationCapsule::SetCapsuleButton(const std::vector<NotificationIconButton> &buttons)
{
    capsuleButton_ = buttons;
}

int32_t NotificationCapsule::GetTime() const
{
    return time_;
}

void NotificationCapsule::SetTime(int32_t time)
{
    time_ = time;
}

std::string NotificationCapsule::Dump()
{
    return "Capsule{ "
            "title = " + title_ +
            ", backgroundColor = " + backgroundColor_ +
            ", content = " + content_ +
            ", icon = " + (icon_ ? "not null" : "null") +
            ", time = " + std::to_string(time_) +
            " }";
}

bool NotificationCapsule::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["title"] = title_;
    jsonObject["backgroundColor"] = backgroundColor_;
    jsonObject["content"] = content_;
    jsonObject["icon"] = AnsImageUtil::PackImage(icon_);

    jsonObject["time"] = time_;
    nlohmann::json capsuleBtnArr = nlohmann::json::array();
    for (auto btn : capsuleButton_) {
        nlohmann::json capsuleBtnObj;
        if (!NotificationJsonConverter::ConvertToJson(&btn, capsuleBtnObj)) {
            ANS_LOGE("Cannot convert button to JSON");
            return false;
        }
        capsuleBtnArr.emplace_back(capsuleBtnObj);
    }
    jsonObject["capsuleButtons"] = capsuleBtnArr;

    return true;
}

NotificationCapsule *NotificationCapsule::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationCapsule *capsule = new (std::nothrow) NotificationCapsule();
    if (capsule == nullptr) {
        ANS_LOGE("null capsule");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("title") != jsonEnd && jsonObject.at("title").is_string()) {
        capsule->title_ = jsonObject.at("title").get<std::string>();
    }

    if (jsonObject.find("backgroundColor") != jsonEnd && jsonObject.at("backgroundColor").is_string()) {
        capsule->backgroundColor_ = jsonObject.at("backgroundColor").get<std::string>();
    }

    if (jsonObject.find("content") != jsonEnd && jsonObject.at("content").is_string()) {
        capsule->content_ = jsonObject.at("content").get<std::string>();
    }

    if (jsonObject.find("icon") != jsonEnd && jsonObject.at("icon").is_string()) {
        auto pmStr             = jsonObject.at("icon").get<std::string>();
        capsule->icon_ = AnsImageUtil::UnPackImage(pmStr);
    }

    if (jsonObject.find("time") != jsonEnd && jsonObject.at("time").is_number_integer()) {
        capsule->time_ = jsonObject.at("time").get<int32_t>();
    }

    if (jsonObject.find("capsuleButtons") != jsonEnd && jsonObject.at("capsuleButtons").is_array()) {
        std::vector<NotificationIconButton> cardButtons;
        for (auto &item : jsonObject.at("capsuleButtons").items()) {
            nlohmann::json cardBtnObject = item.value();
            auto pButton = NotificationJsonConverter::ConvertFromJson<NotificationIconButton>(cardBtnObject);
            if (pButton != nullptr) {
                cardButtons.push_back(*pButton);
                delete pButton;
                pButton = nullptr;
            }
        }
        capsule->capsuleButton_ = cardButtons;
    }

    return capsule;
}

bool NotificationCapsule::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(title_)) {
        ANS_LOGE("Failed to write title");
        return false;
    }

    if (!parcel.WriteString(backgroundColor_)) {
        ANS_LOGE("Failed to write backgroundColor");
        return false;
    }

    if (!parcel.WriteString(content_)) {
        ANS_LOGE("Failed to write content");
        return false;
    }

    bool valid = icon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether icon pixelMap is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(icon_.get())) {
            ANS_LOGE("Failed to write icon");
            return false;
        }
    }

    if (!parcel.WriteInt32(time_)) {
        ANS_LOGE("Write time_ fail.");
        return false;
    }

    parcel.WriteInt32(static_cast<int>(capsuleButton_.size()));
    for (const auto& button : capsuleButton_) {
        if (!parcel.WriteParcelable(&button)) {
            ANS_LOGE("Failed to write card button");
            return false;
        }
    }

    return true;
}

bool NotificationCapsule::ReadFromParcel(Parcel &parcel)
{
    title_ = parcel.ReadString();
    backgroundColor_ = parcel.ReadString();
    content_ = parcel.ReadString();

    bool valid = parcel.ReadBool();
    if (valid) {
        icon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!icon_) {
            ANS_LOGE("Failed to read icon pixelMap");
            return false;
        }
    }

    if (!parcel.ReadInt32(time_)) {
        ANS_LOGE("Read time_ failed.");
        return false;
    }

    auto vsize = static_cast<uint32_t>(parcel.ReadInt32());
    vsize = (vsize < BUTTON_MAX_SIZE) ? vsize : BUTTON_MAX_SIZE;
    capsuleButton_.clear();
    for (uint32_t i = 0; i < vsize; ++i) {
        auto btn = parcel.ReadParcelable<NotificationIconButton>();
        if (btn == nullptr) {
            ANS_LOGE("Failed to read card button");
            return false;
        }
        capsuleButton_.push_back(*btn);
        delete btn;
        btn = nullptr;
    }

    return true;
}

NotificationCapsule *NotificationCapsule::Unmarshalling(Parcel &parcel)
{
    NotificationCapsule *capsule = new (std::nothrow) NotificationCapsule();

    if (capsule && !capsule->ReadFromParcel(parcel)) {
        delete capsule;
        capsule = nullptr;
    }

    return capsule;
}

void NotificationCapsule::ResetIcon()
{
    if (icon_) {
        icon_.reset();
    }
}
}  // namespace Notification
}  // namespace OHOS