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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H

#include <map>
#include <string>
#include <vector>
#include <singleton.h>

#ifdef CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif
#include "nlohmann/json.hpp"
#include "notification_constant.h"
#include "notification_flags.h"

namespace OHOS {
namespace Notification {
class NotificationConfigParse : public DelayedSingleton<NotificationConfigParse> {
public:
    NotificationConfigParse();
    ~NotificationConfigParse() = default;

    bool GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const;
    bool GetCurrentSlotReminder(
        std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const;
    uint32_t GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType) const;
private:
    std::map<NotificationConstant::SlotType, uint32_t> defaultCurrentSlotReminder_;
    std::vector<nlohmann::json> notificationConfigJsons_;

public:
    constexpr static const char* CFG_KEY_NOTIFICATION_SERVICE = "notificationService";
    constexpr static const char* CFG_KEY_SLOT_TYPE_REMINDER = "slotTypeReminder";
    constexpr static const char* CFG_KEY_NAME = "name";
    constexpr static const char* CFG_KEY_REMINDER_FLAGS = "reminderFlags";
    #ifdef CONFIG_POLICY_ENABLE
        constexpr static const char* NOTIFICAITON_CONFIG_FILE = "etc/notification/notification_config.json";
    # else
        constexpr static const char* NOTIFICAITON_CONFIG_FILE = "system/etc/notification/notification_config.json";
    #endif
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H
