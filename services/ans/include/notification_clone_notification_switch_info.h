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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_NOTIFICATION_SWITCH_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_NOTIFICATION_SWITCH_INFO_H

#include <string>

#include "ans_const_define.h"
#include "nlohmann/json.hpp"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationCloneNotificationSwitchInfo {
public:
    /**
     * @brief Default constructor.
     */
    NotificationCloneNotificationSwitchInfo() = default;

    /**
     * @brief Default destructor.
     */
    ~NotificationCloneNotificationSwitchInfo() = default;

    /**
     * @brief Sets the aggregation type.
     *
     * @param switchName Indicates the aggregation type (DEAL, LOGISTICS, or OTHER).
     */
    void SetSwitchName(const std::string &switchName);

    /**
     * @brief Obtains the aggregation type.
     *
     * @return Returns the aggregation type (DEAL, LOGISTICS, or OTHER).
     */
    std::string GetSwitchName() const;

    /**
     * @brief Sets the switch state.
     *
     * @param switchState Indicates the switch state (USER_MODIFIED_OFF, USER_MODIFIED_ON,
     *                     SYSTEM_DEFAULT_OFF, or SYSTEM_DEFAULT_ON).
     */
    void SetSwitchState(const NotificationConstant::SWITCH_STATE &switchState);

    /**
     * @brief Obtains the switch state.
     *
     * @return Returns the switch state (USER_MODIFIED_OFF, USER_MODIFIED_ON,
     *          SYSTEM_DEFAULT_OFF, or SYSTEM_DEFAULT_ON).
     */
    NotificationConstant::SWITCH_STATE GetSwitchState() const;

    /**
     * @brief Marshals the object into a JSON object.
     *
     * @param jsonObject Indicates the JSON object to write to.
     */
    void ToJson(nlohmann::json &jsonObject) const;

    /**
     * @brief Unmarshals the object from a JSON object.
     *
     * @param jsonObject Indicates the JSON object to read from.
     * @return Returns true if successful, false otherwise.
     */
    bool FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Dumps the object information for debugging.
     *
     * @return Returns the dump string.
     */
    std::string Dump() const;

private:
    // JSON key constants
    static constexpr const char *SWITCH_NAME = "switchName";
    static constexpr const char *SWITCH_STATE = "switchState";

    // Member variables
    std::string switchName_ {NotificationConstant::NotificationSwitch::INVALID};
    NotificationConstant::SWITCH_STATE switchState_ {NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_NOTIFICATION_SWITCH_INFO_H