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

#include "notification_trigger.h"

#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *TRIGGER_TYPE = "triggerType";
constexpr const char *TRIGGER_CONFIG_PATH = "triggerConfigPath";
constexpr const char *TRIGGER_CONDITION = "triggerCondition";
constexpr const char *TRIGGER_DISPLAY_TIME = "triggerDisplayTime";
} // namespace
NotificationTrigger::NotificationTrigger(const NotificationConstant::TriggerType &type,
    const NotificationConstant::ConfigPath &configPath,
    const std::shared_ptr<NotificationGeofence> &condition, int32_t displayTime)
    : type_(type), configPath_(configPath), condition_(condition), displayTime_(displayTime)
{}

void NotificationTrigger::SetTriggerType(NotificationConstant::TriggerType type)
{
    type_ = type;
}

NotificationConstant::TriggerType NotificationTrigger::GetTriggerType() const
{
    return type_;
}

void NotificationTrigger::SetConfigPath(NotificationConstant::ConfigPath configPath)
{
    configPath_ = configPath;
}

NotificationConstant::ConfigPath NotificationTrigger::GetConfigPath() const
{
    return configPath_;
}

void NotificationTrigger::SetGeofence(std::shared_ptr<NotificationGeofence> condition)
{
    condition_ = condition;
}

std::shared_ptr<NotificationGeofence> NotificationTrigger::GetGeofence() const
{
    return condition_;
}

void NotificationTrigger::SetDisplayTime(int32_t displayTime)
{
    displayTime_ = displayTime;
}

int32_t NotificationTrigger::GetDisplayTime() const
{
    return displayTime_;
}

bool NotificationTrigger::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        ANS_LOGE("Failed to write trigger type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(configPath_))) {
        ANS_LOGE("Failed to write config path");
        return false;
    }

    bool valid {false};

    valid = condition_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether condition is null");
        return false;
    }

    if (condition_) {
        if (!parcel.WriteParcelable(condition_.get())) {
            ANS_LOGE("Failed to write condition");
            return false;
        }
    }

    if (!parcel.WriteInt32(displayTime_)) {
        ANS_LOGE("Failed to write display time");
        return false;
    }

    return true;
}

NotificationTrigger *NotificationTrigger::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationTrigger();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool NotificationTrigger::ReadFromParcel(Parcel &parcel)
{
    type_ = static_cast<NotificationConstant::TriggerType>(parcel.ReadInt32());
    configPath_ = static_cast<NotificationConstant::ConfigPath>(parcel.ReadInt32());
    bool valid {false};
    valid = parcel.ReadBool();
    if (valid) {
        condition_ = std::shared_ptr<NotificationGeofence>(parcel.ReadParcelable<NotificationGeofence>());
        if (!condition_) {
            ANS_LOGE("null condition");
            return false;
        }
    }
    displayTime_ = parcel.ReadInt32();
    return true;
}

bool NotificationTrigger::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[TRIGGER_TYPE] = static_cast<int32_t>(type_);
    jsonObject[TRIGGER_CONFIG_PATH] = static_cast<int32_t>(configPath_);
    nlohmann::json contentObj;
    if (condition_) {
        if (!NotificationJsonConverter::ConvertToJson(condition_.get(), contentObj)) {
            ANS_LOGE("Cannot convert condition to JSON");
            return false;
        }
    }
    jsonObject[TRIGGER_CONDITION] = contentObj;
    jsonObject[TRIGGER_DISPLAY_TIME] = displayTime_;
    return true;
}

NotificationTrigger *NotificationTrigger::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pNotificationTrigger = new (std::nothrow) NotificationTrigger();
    if (pNotificationTrigger == nullptr) {
        ANS_LOGE("null pNotificationTrigger");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find(TRIGGER_TYPE) != jsonEnd && jsonObject.at(TRIGGER_TYPE).is_number_integer()) {
        auto triggerType  = jsonObject.at(TRIGGER_TYPE).get<int32_t>();
        pNotificationTrigger->type_ = static_cast<NotificationConstant::TriggerType>(triggerType);
    }

    if (jsonObject.find(TRIGGER_CONFIG_PATH) != jsonEnd && jsonObject.at(TRIGGER_CONFIG_PATH).is_number_integer()) {
        auto configPath  = jsonObject.at(TRIGGER_CONFIG_PATH).get<int32_t>();
        pNotificationTrigger->configPath_ = static_cast<NotificationConstant::ConfigPath>(configPath);
    }

    if (!ConvertJsonToNotificationGeofence(pNotificationTrigger, jsonObject)) {
        delete pNotificationTrigger;
        pNotificationTrigger = nullptr;
        return nullptr;
    }

    if (jsonObject.find(TRIGGER_DISPLAY_TIME) != jsonEnd && jsonObject.at(TRIGGER_DISPLAY_TIME).is_number_integer()) {
        pNotificationTrigger->displayTime_ = jsonObject.at(TRIGGER_DISPLAY_TIME).get<int32_t>();
    }

    return pNotificationTrigger;
}

bool NotificationTrigger::ConvertJsonToNotificationGeofence(NotificationTrigger *target,
    const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("null target");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find(TRIGGER_CONDITION) != jsonEnd) {
        auto contentObj = jsonObject.at(TRIGGER_CONDITION);
        if (!contentObj.is_null()) {
            auto pContent = NotificationJsonConverter::ConvertFromJson<NotificationGeofence>(contentObj);
            if (pContent == nullptr) {
                ANS_LOGE("null pContent");
                return false;
            }

            target->condition_ = std::shared_ptr<NotificationGeofence>(pContent);
        }
    }

    return true;
}

std::string NotificationTrigger::Dump() const
{
    return std::to_string(static_cast<int32_t>(type_)) + " " + std::to_string(static_cast<int32_t>(configPath_)) + " " +
        (condition_ ? condition_->Dump() : "null") + " " + std::to_string(displayTime_);
}
}  // namespace Notification
}  // namespace OHOS