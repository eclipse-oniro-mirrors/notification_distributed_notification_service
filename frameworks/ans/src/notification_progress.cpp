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

#include "notification_progress.h"

#include <cstdint>
#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type


#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel

namespace OHOS {
namespace Notification {

int32_t NotificationProgress::GetMaxValue() const
{
    return maxValue_;
}

void NotificationProgress::SetMaxValue(int32_t maxValue)
{
    maxValue_ = maxValue;
}

int32_t NotificationProgress::GetCurrentValue() const
{
    return currentValue_;
}

void NotificationProgress::SetCurrentValue(int32_t curValue)
{
    currentValue_ = curValue;
}

bool NotificationProgress::GetIsPercentage() const
{
    return isPercentage_;
}

void NotificationProgress::SetIsPercentage(bool isPercentage)
{
    isPercentage_ = isPercentage;
}


std::string NotificationProgress::Dump()
{
    return "Progress{ "
            "maxValue = " + std::to_string(maxValue_) +
            ", currentValue = " + std::to_string(currentValue_) +
            ", isPercentage = " + std::to_string(isPercentage_) +
            " }";
}

bool NotificationProgress::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["maxValue"] = maxValue_;
    jsonObject["currentValue"] = currentValue_;
    jsonObject["isPercentage"] = isPercentage_;

    return true;
}

NotificationProgress *NotificationProgress::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationProgress *progress = new (std::nothrow) NotificationProgress();
    if (progress == nullptr) {
        ANS_LOGE("Failed to create capsule instance");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("maxValue") != jsonEnd && jsonObject.at("maxValue").is_number_integer()) {
        progress->maxValue_ = jsonObject.at("maxValue").get<int32_t>();
    }

    if (jsonObject.find("currentValue") != jsonEnd && jsonObject.at("currentValue").is_number_integer()) {
        progress->currentValue_ = jsonObject.at("currentValue").get<int32_t>();
    }

    if (jsonObject.find("isPercentage") != jsonEnd && jsonObject.at("isPercentage").is_boolean()) {
        progress->isPercentage_ = jsonObject.at("isPercentage").get<bool>();
    }

    return progress;
}

bool NotificationProgress::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(maxValue_)) {
        ANS_LOGE("Failed to write maxValue");
        return false;
    }

    if (!parcel.WriteInt32(currentValue_)) {
        ANS_LOGE("Failed to write currentValue");
        return false;
    }

    if (!parcel.WriteBool(isPercentage_)) {
        ANS_LOGE("Failed to write isPercentage");
        return false;
    }
    return true;
}

bool NotificationProgress::ReadFromParcel(Parcel &parcel)
{
    maxValue_ = parcel.ReadInt32();
    currentValue_ = parcel.ReadInt32();
    isPercentage_ = parcel.ReadBool();

    return true;
}

NotificationProgress *NotificationProgress::Unmarshalling(Parcel &parcel)
{
    NotificationProgress *progress = new (std::nothrow) NotificationProgress();

    if (progress && !progress->ReadFromParcel(parcel)) {
        delete progress;
        progress = nullptr;
    }

    return progress;
}
}  // namespace Notification
}  // namespace OHOS
