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

#include "notification_time.h"

#include <cstdint>
#include <string>             // for basic_string, operator+, basic_string<>...
#include <memory>             // for shared_ptr, shared_ptr<>::element_type


#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"  // for json, basic_json<>::object_t, basic_json
#include "parcel.h"           // for Parcel

namespace OHOS {
namespace Notification {

int32_t NotificationTime::GetInitialTime() const
{
    return initialTime_;
}

void NotificationTime::SetInitialTime(int32_t time)
{
    initialTime_ = time;
}

bool NotificationTime::GetIsCountDown() const
{
    return isCountDown_;
}

void NotificationTime::SetIsCountDown(bool flag)
{
    isCountDown_ = flag;
}
    
bool NotificationTime::GetIsPaused() const
{
    return isPaused_;
}

void NotificationTime::SetIsPaused(bool flag)
{
    isPaused_ = flag;
}

bool NotificationTime::GetIsInTitle() const
{
    return isInTitle_;
}

void NotificationTime::SetIsInTitle(bool flag)
{
    isInTitle_ = flag;
}

std::string NotificationTime::Dump()
{
    return "Time{ "
            "initialTime = " + std::to_string(initialTime_) +
            ", isCountDown = " + std::to_string(isCountDown_) +
            ", isPaused = " + std::to_string(isPaused_) +
            ", isInTitle = " + std::to_string(isInTitle_) +
            " }";
}

bool NotificationTime::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["initialTime"] = initialTime_;
    jsonObject["isCountDown"] = isCountDown_;
    jsonObject["isPaused"] = isPaused_;
    jsonObject["isInTitle"] = isInTitle_;

    return true;
}

NotificationTime *NotificationTime::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationTime *time = new (std::nothrow) NotificationTime();
    if (time == nullptr) {
        ANS_LOGE("Failed to create time instance");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("initialTime") != jsonEnd && jsonObject.at("initialTime").is_number_integer()) {
        time->initialTime_ = jsonObject.at("initialTime").get<int32_t>();
    }

    if (jsonObject.find("isCountDown") != jsonEnd && jsonObject.at("isCountDown").is_boolean()) {
        time->isCountDown_ = jsonObject.at("isCountDown").get<bool>();
    }

    if (jsonObject.find("isPaused") != jsonEnd && jsonObject.at("isPaused").is_boolean()) {
        time->isPaused_ = jsonObject.at("isPaused").get<bool>();
    }

    if (jsonObject.find("isInTitle") != jsonEnd && jsonObject.at("isInTitle").is_boolean()) {
        time->isInTitle_ = jsonObject.at("isInTitle").get<bool>();
    }

    return time;
}

bool NotificationTime::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(initialTime_)) {
        ANS_LOGE("Failed to write initialTime");
        return false;
    }

    if (!parcel.WriteBool(isCountDown_)) {
        ANS_LOGE("Failed to write isCountDown");
        return false;
    }

    if (!parcel.WriteBool(isPaused_)) {
        ANS_LOGE("Failed to write isPaused");
        return false;
    }

    if (!parcel.WriteBool(isInTitle_)) {
        ANS_LOGE("Failed to write isInTitle");
        return false;
    }

    return true;
}

bool NotificationTime::ReadFromParcel(Parcel &parcel)
{
    initialTime_ = parcel.ReadInt32();
    isCountDown_ = parcel.ReadBool();
    isPaused_ = parcel.ReadBool();
    isInTitle_ = parcel.ReadBool();

    return true;
}

NotificationTime *NotificationTime::Unmarshalling(Parcel &parcel)
{
    NotificationTime *time = new (std::nothrow) NotificationTime();

    if (time && !time->ReadFromParcel(parcel)) {
        delete time;
        time = nullptr;
    }

    return time;
}
}  // namespace Notification
}  // namespace OHOS