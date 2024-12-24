/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "notification_local_live_view_content.h"

#include <cstdint>
#include <string>                            // for basic_string, operator+
#include <algorithm>                         // for min
#include <vector>

#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"                 // for json, basic_json<>::obje...
#include "notification_action_button.h"
#include "notification_basic_content.h"      // for NotificationBasicContent
#include "notification_capsule.h"
#include "notification_content.h"
#include "notification_json_convert.h"
#include "notification_progress.h"
#include "notification_local_live_view_button.h"
#include "notification_time.h"
#include "parcel.h"                          // for Parcel

namespace OHOS {
namespace Notification {

void NotificationLocalLiveViewContent::SetType(int32_t type)
{
    type_ = type;
}

int32_t NotificationLocalLiveViewContent::GetType()
{
    return type_;
}

void NotificationLocalLiveViewContent::SetCapsule(NotificationCapsule capsule)
{
    capsule_ = capsule;
}

NotificationCapsule NotificationLocalLiveViewContent::GetCapsule()
{
    return capsule_;
}

void NotificationLocalLiveViewContent::SetButton(NotificationLocalLiveViewButton button)
{
    button_ = button;
}

NotificationLocalLiveViewButton NotificationLocalLiveViewContent::GetButton()
{
    return button_;
}

void NotificationLocalLiveViewContent::SetCardButton(std::vector<NotificationIconButton> buttons)
{
    card_button_ = buttons;
}

std::vector<NotificationIconButton> NotificationLocalLiveViewContent::GetCardButton()
{
    return card_button_;
}

void NotificationLocalLiveViewContent::SetProgress(NotificationProgress progress)
{
    progress_ = progress;
}

NotificationProgress NotificationLocalLiveViewContent::GetProgress()
{
    return progress_;
}

void NotificationLocalLiveViewContent::SetTime(NotificationTime time)
{
    time_ = time;
}

NotificationTime NotificationLocalLiveViewContent::GetTime()
{
    return time_;
}

void NotificationLocalLiveViewContent::addFlag(int32_t flag)
{
    flags_.emplace_back(flag);
}

bool NotificationLocalLiveViewContent::isFlagExist(int32_t flag)
{
    auto it = std::find(flags_.begin(), flags_.end(), flag);
    if (it != flags_.end()) {
        return true;
    } else {
        return false;
    }
}

void NotificationLocalLiveViewContent::SetLiveviewType(int32_t type)
{
    liveviewType_ = type;
}

int32_t NotificationLocalLiveViewContent::GetLiveviewType()
{
    return liveviewType_;
}

std::string NotificationLocalLiveViewContent::Dump()
{
    return "NotificationLocalLiveViewContent{ " + NotificationBasicContent::Dump() +
            ", type = " + std::to_string(type_) +
            ", capsule = " + capsule_.Dump() +
            ", button = " + button_.Dump() +
            ", progress = " + progress_.Dump() +
            ", time = " + time_.Dump() +
            ", liveviewType = " + std::to_string(liveviewType_) +
            " }";
}

bool NotificationLocalLiveViewContent::ToJson(nlohmann::json &jsonObject) const
{
    if (!NotificationBasicContent::ToJson(jsonObject)) {
        ANS_LOGE("Cannot convert basicContent to JSON");
        return false;
    }

    nlohmann::json capsuleObj;
    if (!NotificationJsonConverter::ConvertToJson(&capsule_, capsuleObj)) {
        ANS_LOGE("Cannot convert capsule to JSON");
        return false;
    }

    nlohmann::json buttonObj;
    if (!NotificationJsonConverter::ConvertToJson(&button_, buttonObj)) {
        ANS_LOGE("Cannot convert button to JSON");
        return false;
    }

    nlohmann::json progressObj;
    if (!NotificationJsonConverter::ConvertToJson(&progress_, progressObj)) {
        ANS_LOGE("Cannot convert progress to JSON");
        return false;
    }

    nlohmann::json timeObj;
    if (!NotificationJsonConverter::ConvertToJson(&time_, timeObj)) {
        ANS_LOGE("Cannot convert time to JSON");
        return false;
    }

    nlohmann::json cardBtnArr = nlohmann::json::array();
    for (auto btn : card_button_) {
        nlohmann::json cardBtnObj;
        if (!NotificationJsonConverter::ConvertToJson(&btn, cardBtnObj)) {
            ANS_LOGE("Cannot convert button to JSON");
            return false;
        }
        cardBtnArr.emplace_back(cardBtnObj);
    }

    jsonObject["type"] = type_;
    jsonObject["capsule"] = capsuleObj;
    jsonObject["button"] = buttonObj;
    jsonObject["cardButton"] = cardBtnArr;
    jsonObject["progress"] = progressObj;
    jsonObject["time"] = timeObj;
    jsonObject["flags"] = nlohmann::json(flags_);
    jsonObject["liveviewType"] = liveviewType_;

    return true;
}

NotificationLocalLiveViewContent *NotificationLocalLiveViewContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pContent = new (std::nothrow) NotificationLocalLiveViewContent();
    if (pContent == nullptr) {
        ANS_LOGE("Failed to create localLiveViewContent instance");
        return nullptr;
    }

    pContent->ReadFromJson(jsonObject);

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("typeCode") != jsonEnd && jsonObject.at("typeCode").is_number_integer()) {
        pContent->type_ = jsonObject.at("typeCode").get<int32_t>();
    }

    if (jsonObject.find("capsule") != jsonEnd) {
        auto capsuleObj = jsonObject.at("capsule");
        auto pCapsule = NotificationJsonConverter::ConvertFromJson<NotificationCapsule>(capsuleObj);
        if (pCapsule != nullptr) {
            pContent->capsule_ = *pCapsule;
            delete pCapsule;
            pCapsule = nullptr;
        }
    }

    if (jsonObject.find("button") != jsonEnd) {
        auto buttonObj = jsonObject.at("button");
        auto pButton = NotificationJsonConverter::ConvertFromJson<NotificationLocalLiveViewButton>(buttonObj);
        if (pButton != nullptr) {
            pContent->button_ = *pButton;
            delete pButton;
            pButton = nullptr;
        }
    }

    if (jsonObject.find("cardButton") != jsonEnd && jsonObject.at("cardButton").is_array()) {
        std::vector<NotificationIconButton> cardButtons;
        for (auto &item : jsonObject.at("cardButton").items()) {
            nlohmann::json cardBtnObject = item.value();
            auto pButton = NotificationJsonConverter::ConvertFromJson<NotificationIconButton>(cardBtnObject);
            if (pButton != nullptr) {
                cardButtons.push_back(*pButton);
                delete pButton;
                pButton = nullptr;
            }
        }
        pContent->card_button_ = cardButtons;
    }

    if (jsonObject.find("progress") != jsonEnd) {
        auto progressObj = jsonObject.at("progress");
        auto pProgress = NotificationJsonConverter::ConvertFromJson<NotificationProgress>(progressObj);
        if (pProgress != nullptr) {
            pContent->progress_ = *pProgress;
            delete pProgress;
            pProgress = nullptr;
        }
    }

    if (jsonObject.find("time") != jsonEnd) {
        auto timeObj = jsonObject.at("time");
        auto pTime = NotificationJsonConverter::ConvertFromJson<NotificationTime>(timeObj);
        if (pTime != nullptr) {
            pContent->time_ = *pTime;
            delete pTime;
            pTime = nullptr;
        }
    }

    if (jsonObject.find("flags") != jsonEnd && jsonObject.at("flags").is_array()) {
        pContent->flags_ = jsonObject.at("flags").get<std::vector<int32_t>>();
    }

    if (jsonObject.find("liveviewType") != jsonEnd && jsonObject.at("liveviewType").is_number_integer()) {
        pContent->liveviewType_ = jsonObject.at("liveviewType").get<int32_t>();
    }

    return pContent;
}

bool NotificationLocalLiveViewContent::Marshalling(Parcel &parcel) const
{
    if (!NotificationBasicContent::Marshalling(parcel)) {
        ANS_LOGE("Failed to write basic");
        return false;
    }

    if (contentType_ == static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT)) {
        return true;
    }

    if (!parcel.WriteInt32(type_)) {
        ANS_LOGE("Write type fail.");
        return false;
    }

    if (!parcel.WriteParcelable(&capsule_)) {
        ANS_LOGE("Failed to write capsule");
        return false;
    }

    if (!parcel.WriteParcelable(&button_)) {
        ANS_LOGE("Failed to write button");
        return false;
    }

	parcel.WriteInt32(static_cast<int>(card_button_.size()));
    for (const auto& button : card_button_) {
        if (!parcel.WriteParcelable(&button)) {
            ANS_LOGE("Failed to write card button");
            return false;
        }
    }

    if (!parcel.WriteParcelable(&progress_)) {
        ANS_LOGE("Failed to write progress");
        return false;
    }

    if (!parcel.WriteParcelable(&time_)) {
        ANS_LOGE("Failed to write time");
        return false;
    }

    if (!parcel.WriteInt32Vector(flags_)) {
        ANS_LOGE("Failed to write flags");
        return false;
    }

    if (!parcel.WriteInt32(liveviewType_)) {
        ANS_LOGE("Write liveviewType fail.");
        return false;
    }

    return true;
}

NotificationLocalLiveViewContent *NotificationLocalLiveViewContent::Unmarshalling(Parcel &parcel)
{
    auto pContent = new (std::nothrow) NotificationLocalLiveViewContent();
    if ((pContent != nullptr) && !pContent->ReadFromParcel(parcel)) {
        delete pContent;
        pContent = nullptr;
    }

    return pContent;
}

bool NotificationLocalLiveViewContent::ReadFromParcel(Parcel &parcel)
{
    if (!NotificationBasicContent::ReadFromParcel(parcel)) {
        ANS_LOGE("Failed to read basic");
        return false;
    }

    if (!parcel.ReadInt32(type_)) {
        ANS_LOGE("Read type failed.");
        return false;
    }

    auto pCapsule = parcel.ReadParcelable<NotificationCapsule>();
    if (pCapsule == nullptr) {
        ANS_LOGE("Failed to read capsule");
        return false;
    }
    capsule_ = *pCapsule;
    delete pCapsule;
    pCapsule = nullptr;

    auto pButton = parcel.ReadParcelable<NotificationLocalLiveViewButton>();
    if (pButton == nullptr) {
        ANS_LOGE("Failed to read button");
        return false;
    }
    button_ = *pButton;
    delete pButton;
    pButton = nullptr;

    auto vsize = parcel.ReadInt32();
    vsize = (vsize < BUTTON_MAX_SIZE) ? vsize : BUTTON_MAX_SIZE;
    card_button_.clear();
    for (int i = 0; i < vsize; ++i) {
        auto btn = parcel.ReadParcelable<NotificationIconButton>();
        if (btn == nullptr) {
            ANS_LOGE("Failed to read card button");
            return false;
        }
        card_button_.push_back(*btn);
        delete btn;
        btn = nullptr;
    }

    auto pProgress = parcel.ReadParcelable<NotificationProgress>();
    if (pProgress == nullptr) {
        ANS_LOGE("Failed to read progress");
        return false;
    }
    progress_ = *pProgress;
    delete pProgress;
    pProgress = nullptr;

    auto pTime = parcel.ReadParcelable<NotificationTime>();
    if (pTime == nullptr) {
        ANS_LOGE("Failed to read time");
        return false;
    }
    time_ = *pTime;
    delete pTime;
    pTime = nullptr;

    if (!parcel.ReadInt32Vector(&flags_)) {
        ANS_LOGE("Failed to read flags");
        return false;
    }

    if (!parcel.ReadInt32(liveviewType_)) {
        ANS_LOGE("Read liveviewType_ failed.");
        return false;
    }

    return true;
}

void NotificationLocalLiveViewContent::ClearButton()
{
    button_.ClearButtonIcons();
    button_.ClearButtonIconsResource();
}

void NotificationLocalLiveViewContent::ClearCapsuleIcon()
{
    capsule_.ResetIcon();
}
}  // namespace Notification
}  // namespace OHOS
