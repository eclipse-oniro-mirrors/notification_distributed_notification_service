/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "notification_icon_button.h"

#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type
#include <sstream>


#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel

namespace OHOS {
namespace Notification {
using ResourceVectorPtr = std::vector<std::shared_ptr<ResourceManager::Resource>>;

const std::shared_ptr<ResourceManager::Resource> NotificationIconButton::GetIconResource() const
{
    return iconResource_;
}

void NotificationIconButton::SetIconResource(const std::shared_ptr<ResourceManager::Resource> &iconResource)
{
    iconResource_ = iconResource;
}


std::string NotificationIconButton::GetText() const
{
    return text_;
}

void NotificationIconButton::SetText(const std::string &text)
{
    text_ = text;
}

std::string NotificationIconButton::GetName() const
{
    return name_;
}

void NotificationIconButton::SetName(const std::string &name)
{
    name_ = name;
}

bool NotificationIconButton::GetHidePanel() const
{
    return hidePanel_;
}

void NotificationIconButton::SetHidePanel(bool hidePanel)
{
    hidePanel_ = hidePanel;
}

void NotificationIconButton::ClearButtonIconsResource()
{
}

std::string NotificationIconButton::Dump()
{
    return "NotificationIconButton {"
            "name = " + name_ +
            ", text = " + text_ +
            ", hidePanel = " + std::to_string(hidePanel_) +
            " }";
}

bool NotificationIconButton::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["text"] = text_;
    jsonObject["name"] = name_;
    jsonObject["hidePanel"] = hidePanel_;

    nlohmann::json resourceObj;
    resourceObj["id"] = iconResource_->id;
    resourceObj["bundleName"] = iconResource_->bundleName;
    resourceObj["moduleName"] = iconResource_->moduleName;
    jsonObject["iconResource"] = resourceObj;
    return true;
}

NotificationIconButton *NotificationIconButton::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *button = new (std::nothrow) NotificationIconButton();
    if (button == nullptr) {
        ANS_LOGE("Failed to create icon button");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("text") != jsonEnd && jsonObject.at("text").is_string()) {
        button->SetText(jsonObject.at("text").get<std::string>());
    }

    if (jsonObject.find("name") != jsonEnd && jsonObject.at("name").is_string()) {
        button->SetName(jsonObject.at("name").get<std::string>());
    }

    if (jsonObject.find("hidePanel") != jsonEnd && jsonObject.at("hidePanel").is_boolean()) {
        button->SetHidePanel(jsonObject.at("hidePanel").get<bool>());
    }

    if (jsonObject.find("iconResource") != jsonEnd) {
        auto resources = jsonObject.at("iconResource");
        auto resourceObj = std::make_shared<Global::Resource::ResourceManager::Resource>();
        if (ResourceFromJson(resources, resourceObj)) {
            button->SetIconResource(resourceObj);
        }
    }
    return button;
}

bool NotificationIconButton::ResourceFromJson(const nlohmann::json &resource,
    std::shared_ptr<ResourceManager::Resource>& resourceObj)
{
    const auto &jsonEnd = resource.cend();
    int resourceCount = BUTTON_RESOURCE_SIZE;
    if (resource.find("bundleName") != jsonEnd && resource.at("bundleName").is_string()) {
        resourceCount--;
        resourceObj->bundleName = resource.at("bundleName").get<std::string>();
    }
    if (resource.find("moduleName") != jsonEnd && resource.at("moduleName").is_string()) {
        resourceCount--;
        resourceObj->moduleName = resource.at("moduleName").get<std::string>();
    }
    if (resource.find("id") != jsonEnd && resource.at("id").is_number_integer()) {
        resourceCount--;
        resourceObj->id = resource.at("id").get<int32_t>();
    }
    if (resourceCount == 0) {
        return true;
    }
    ANS_LOGE("Resource from json failed.");
    return false;
}

bool NotificationIconButton::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(text_)) {
        ANS_LOGE("Failed to write text");
        return false;
    }

    if (!parcel.WriteString(name_)) {
        ANS_LOGE("Failed to write name");
        return false;
    }

    if (!parcel.WriteBool(hidePanel_)) {
        ANS_LOGE("Failed to write hidePanel");
        return false;
    }

    std::vector<std::string> iconsResource  = {};
    iconsResource.push_back(iconResource_->bundleName);
    iconsResource.push_back(iconResource_->moduleName);
    iconsResource.push_back(std::to_string(iconResource_->id));
    if (!parcel.WriteStringVector(iconsResource)) {
        ANS_LOGE("Failed to write button icon resource");
        return false;
    }
    return true;
}

NotificationIconButton *NotificationIconButton::Unmarshalling(Parcel &parcel)
{
    NotificationIconButton *button = new (std::nothrow) NotificationIconButton();

    if (button && !button->ReadFromParcel(parcel)) {
        delete button;
        button = nullptr;
    }
    return button;
}

bool NotificationIconButton::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(text_)) {
        ANS_LOGE("Failed to read text");
        return false;
    }

    if (!parcel.ReadString(name_)) {
        ANS_LOGE("Failed to read name");
        return false;
    }

    if (!parcel.ReadBool(hidePanel_)) {
        ANS_LOGE("Failed to read hidePanel");
        return false;
    }

    std::vector<std::string> iconsResource;
    if (!parcel.ReadStringVector(&iconsResource)) {
        ANS_LOGE("Failed to read button names");
        return false;
    }
    if (iconsResource.size() < BUTTON_RESOURCE_SIZE) {
        ANS_LOGE("Invalid input for button icons resource");
        return false;
    }
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->bundleName = iconsResource[RESOURCE_BUNDLENAME_INDEX];
    resource->moduleName = iconsResource[RESOURCE_MODULENAME_INDEX];
    std::stringstream sin(iconsResource[RESOURCE_ID_INDEX]);
    int32_t checknum;
    if (!(sin >> checknum)) {
        ANS_LOGE("Invalid input for button icons resource");
        return false;
    }
    resource->id = std::stoi(iconsResource[RESOURCE_ID_INDEX]);
    iconResource_ = resource;

    return true;
}
}
}