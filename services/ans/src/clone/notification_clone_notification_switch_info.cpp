/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_clone_notification_switch_info.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
void NotificationCloneNotificationSwitchInfo::SetSwitchName(const std::string &switchName)
{
    switchName_ = switchName;
}

std::string NotificationCloneNotificationSwitchInfo::GetSwitchName() const
{
    return switchName_;
}

void NotificationCloneNotificationSwitchInfo::SetSwitchState(const NotificationConstant::SWITCH_STATE &switchState)
{
    switchState_ = switchState;
}

NotificationConstant::SWITCH_STATE NotificationCloneNotificationSwitchInfo::GetSwitchState() const
{
    return switchState_;
}

void NotificationCloneNotificationSwitchInfo::ToJson(nlohmann::json &jsonObject) const
{
    // Write aggregation type (only if not empty)
    if (!switchName_.empty()) {
        jsonObject[SWITCH_NAME] = switchName_;
    }

    // Write switch state (convert enum to int32_t)
    jsonObject[SWITCH_STATE] = static_cast<int32_t>(switchState_);
}

bool NotificationCloneNotificationSwitchInfo::FromJson(const nlohmann::json &jsonObject)
{
    // Validate JSON object
    if (jsonObject.is_null() || !jsonObject.is_object() || jsonObject.is_discarded()) {
        ANS_LOGE("Invalid JSON object");
        return false;
    }

    // Parse aggregation type
    if (jsonObject.contains(SWITCH_NAME) && jsonObject[SWITCH_NAME].is_string()) {
        switchName_ = jsonObject.at(SWITCH_NAME).get<std::string>();
    }

    // Parse switch state
    if (jsonObject.contains(SWITCH_STATE) && jsonObject[SWITCH_STATE].is_number()) {
        int32_t switchStateValue = jsonObject.at(SWITCH_STATE).get<int32_t>();
        switchState_ = static_cast<NotificationConstant::SWITCH_STATE>(switchStateValue);
    }

    return true;
}

std::string NotificationCloneNotificationSwitchInfo::Dump() const
{
    std::string dumpStr = "NotificationCloneNotificationSwitchInfo{";
    dumpStr += "switchName=" + switchName_ + ", ";
    dumpStr += "switchState=" + std::to_string(static_cast<int32_t>(switchState_));
    dumpStr += "}";
    return dumpStr;
}
}  // namespace Notification
}  // namespace OHOS