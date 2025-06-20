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

#include "notification_button_option.h"

#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type


#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel

namespace OHOS {
namespace Notification {

void NotificationButtonOption::SetButtonName(const std::string &buttonName)
{
    buttonName_ = buttonName;
}

std::string NotificationButtonOption::GetButtonName() const
{
    return buttonName_;
}

std::string NotificationButtonOption::Dump()
{
    return "NotificationButtonOption{ "
            "buttonName = " + buttonName_ +
            " }";
}

bool NotificationButtonOption::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["buttonName"] = buttonName_;
    return true;
}

NotificationButtonOption *NotificationButtonOption::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationButtonOption *button = new (std::nothrow) NotificationButtonOption();
    if (button == nullptr) {
        ANS_LOGE("null button");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("buttonName") != jsonEnd && jsonObject.at("buttonName").is_string()) {
        button->buttonName_ = jsonObject.at("buttonName").get<std::string>();
    }

    return button;
}

bool NotificationButtonOption::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(buttonName_)) {
        ANS_LOGE("Failed to write buttonName");
        return false;
    }

    return true;
}

bool NotificationButtonOption::ReadFromParcel(Parcel &parcel)
{
    buttonName_ = parcel.ReadString();

    return true;
}

NotificationButtonOption *NotificationButtonOption::Unmarshalling(Parcel &parcel)
{
    NotificationButtonOption *button = new (std::nothrow) NotificationButtonOption();

    if (button && !button->ReadFromParcel(parcel)) {
        delete button;
        button = nullptr;
    }

    return button;
}
}  // namespace Notification
}  // namespace OHOS