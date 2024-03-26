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

    return true;
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
                return nullptr;
            }
            button->buttonIcons_.emplace_back(pIcon);
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
}  // namespace Notification
}  // namespace OHOS
