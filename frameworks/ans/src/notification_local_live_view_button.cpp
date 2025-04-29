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

#include "notification_local_live_view_button.h"

#include <cstdint>
#include <sstream>
#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type
#include <vector>

#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "notification_button_option.h"
#include "notification_json_convert.h"
#include "parcel.h"           // for Parcel
#include "pixel_map.h"        // for PixelMap

namespace OHOS {
namespace Notification {
const uint32_t BUTTON_MAX_SIZE = 3;
const uint32_t BUTTON_RESOURCE_SIZE = 3;
const uint32_t RESOURCE_BUNDLENAME_INDEX = 0;
const uint32_t RESOURCE_MODULENAME_INDEX = 1;
const uint32_t RESOURCE_ID_INDEX = 2;
using ResourceVectorPtr = std::vector<std::shared_ptr<ResourceManager::Resource>>;

std::vector<std::string> NotificationLocalLiveViewButton::GetAllButtonNames() const
{
    return buttonNames_;
}

void NotificationLocalLiveViewButton::addSingleButtonName(const std::string &buttonName)
{
    if (buttonNames_.size() >= BUTTON_MAX_SIZE) {
        ANS_LOGW("already added 3 buttonOption");
        return;
    }

    buttonNames_.emplace_back(buttonName);
}

std::vector<std::shared_ptr<Media::PixelMap>> NotificationLocalLiveViewButton::GetAllButtonIcons() const
{
    return buttonIcons_;
}

void NotificationLocalLiveViewButton::addSingleButtonIcon(std::shared_ptr<Media::PixelMap> &icon)
{
    if (buttonIcons_.size() >= BUTTON_MAX_SIZE) {
        ANS_LOGW("already added 3 buttonIcon");
        return;
    }

    buttonIcons_.emplace_back(icon);
}

ResourceVectorPtr NotificationLocalLiveViewButton::GetAllButtonIconResource() const
{
    return buttonIconsResource_;
}

void NotificationLocalLiveViewButton::addSingleButtonIconResource(
    std::shared_ptr<ResourceManager::Resource> &iconResource)
{
    if (buttonIcons_.size() >= BUTTON_MAX_SIZE) {
        ANS_LOGW("already added 3 buttonIcon");
        return;
    }

    buttonIconsResource_.emplace_back(iconResource);
}

std::string NotificationLocalLiveViewButton::Dump()
{
    return "";
}

bool NotificationLocalLiveViewButton::ToJson(nlohmann::json &jsonObject) const
{
    nlohmann::json buttonsArr = nlohmann::json::array();

    jsonObject["names"] = nlohmann::json(buttonNames_);

    nlohmann::json iconsArr = nlohmann::json::array();
    for (auto &btn : buttonIcons_) {
        if (!btn) {
            continue;
        }
        nlohmann::json btnObj = AnsImageUtil::PackImage(btn);
        iconsArr.emplace_back(btnObj);
    }
    jsonObject["icons"] = iconsArr;

    nlohmann::json iconResourceArr = nlohmann::json::array();
    for (const auto &resource : buttonIconsResource_) {
        if (!resource) {
            continue;
        }
        nlohmann::json resourceObj;
        resourceObj["id"] = resource->id;
        resourceObj["bundleName"] = resource->bundleName;
        resourceObj["moduleName"] = resource->moduleName;
        iconResourceArr.emplace_back(resourceObj);
    }
    jsonObject["iconResources"] = iconResourceArr;

    return true;
}

bool NotificationLocalLiveViewButton::ResourceFromJson(const nlohmann::json &resource,
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
        resourceObj->id = static_cast<uint32_t>(resource.at("id").get<int32_t>());
    }
    if (resourceCount == 0) {
        return true;
    }
    ANS_LOGE("Resource from json failed.");
    return false;
}

NotificationLocalLiveViewButton *NotificationLocalLiveViewButton::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationLocalLiveViewButton *button = new (std::nothrow) NotificationLocalLiveViewButton();
    if (button == nullptr) {
        ANS_LOGE("Failed to create capsule instance");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("names") != jsonEnd && jsonObject.at("names").is_array()) {
        button->buttonNames_ = jsonObject.at("names").get<std::vector<std::string>>();
    }

    if (jsonObject.find("icons") != jsonEnd) {
        auto iconArr = jsonObject.at("icons");
        for (auto &iconObj : iconArr) {
            if (!iconObj.is_string()) {
                continue;
            }
            auto pIcon = AnsImageUtil::UnPackImage(iconObj.get<std::string>());
            if (pIcon == nullptr) {
                ANS_LOGE("Failed to parse button icon");
                delete button;
                return nullptr;
            }
            button->buttonIcons_.emplace_back(pIcon);
        }
    }

    if (jsonObject.find("iconResources") != jsonEnd) {
        auto resourcesArr = jsonObject.at("iconResources");
        for (auto &resource : resourcesArr) {
            auto resourceObj = std::make_shared<Global::Resource::ResourceManager::Resource>();
            if (ResourceFromJson(resource, resourceObj)) {
                button->buttonIconsResource_.emplace_back(resourceObj);
            }
        }
    }

    return button;
}

bool NotificationLocalLiveViewButton::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(buttonNames_)) {
        ANS_LOGE("Failed to write buttonNames");
        return false;
    }

    if (!parcel.WriteUint64(buttonIcons_.size())) {
        ANS_LOGE("Failed to write the size of buttonIcons");
        return false;
    }

    for (auto it = buttonIcons_.begin(); it != buttonIcons_.end(); ++it) {
        if (!parcel.WriteParcelable(it->get())) {
            ANS_LOGE("Failed to write buttonIcons");
            return false;
        }
    }

    if (!parcel.WriteUint64(buttonIconsResource_.size())) {
        ANS_LOGE("Failed to write the size of buttonIcons");
        return false;
    }

    for (auto it = buttonIconsResource_.begin(); it != buttonIconsResource_.end(); ++it) {
        std::vector<std::string> iconsResource  = {};
        // Insertion cannot be changed, Marshalling and Unmarshalling need to match
        iconsResource.push_back((*it)->bundleName);
        iconsResource.push_back((*it)->moduleName);
        iconsResource.push_back(std::to_string((*it)->id));
        if (!parcel.WriteStringVector(iconsResource)) {
            ANS_LOGE("Failed to write button icon resource");
            return false;
        }
    }

    return true;
}

bool NotificationLocalLiveViewButton::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&buttonNames_)) {
        ANS_LOGE("Failed to read button names");
        return false;
    }

    auto vsize = parcel.ReadUint64();
    vsize = (vsize < BUTTON_MAX_SIZE) ? vsize : BUTTON_MAX_SIZE;
    for (uint64_t it = 0; it < vsize; ++it) {
        auto member = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (member == nullptr) {
            buttonIcons_.clear();
            ANS_LOGE("Failed to read LocalLiveViewButton");
            return false;
        }

        buttonIcons_.emplace_back(member);
    }

    vsize = parcel.ReadUint64();
    vsize = (vsize < BUTTON_MAX_SIZE) ? vsize : BUTTON_MAX_SIZE;
    for (uint64_t it = 0; it < vsize; ++it) {
        std::vector<std::string> iconsResource  = {};
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
        resource->id = atoi(iconsResource[RESOURCE_ID_INDEX].c_str());
        buttonIconsResource_.emplace_back(resource);
    }

    return true;
}

NotificationLocalLiveViewButton *NotificationLocalLiveViewButton::Unmarshalling(Parcel &parcel)
{
    NotificationLocalLiveViewButton *button = new (std::nothrow) NotificationLocalLiveViewButton();

    if (button && !button->ReadFromParcel(parcel)) {
        delete button;
        button = nullptr;
    }

    return button;
}

void NotificationLocalLiveViewButton::ClearButtonIcons()
{
    buttonIcons_.clear();
}

void NotificationLocalLiveViewButton::ClearButtonIconsResource()
{
    buttonIconsResource_.clear();
}
}  // namespace Notification
}  // namespace OHOS
