/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_AFFECTED_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_AFFECTED_H

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "notification_flags.h"

namespace OHOS {
namespace Notification {
class ReminderAffected {
public:
    static bool ValidStatus(const nlohmann::json &root, std::string &status);
    static bool ValidAndGetAffectedBy(
        const nlohmann::json &affectedByJson, std::vector<std::pair<std::string, std::string>> &affectedBy);

    bool FromJson(const nlohmann::json &root);
    std::vector<std::pair<std::string, std::string>> affectedBy_;
    std::string status_;
    std::shared_ptr<NotificationFlags> reminderFlags_;

    constexpr static const char* AFFECTED_BY = "affectedBy";
    constexpr static const char* DEVICE_TYPE = "deviceType";
    constexpr static const char* STATUS = "status";
    static constexpr char STATUS_DEFAULT = 'x';
    static constexpr char STATUS_DISABLE = '0';
    static constexpr char STATUS_ENABLE = '1';
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_AFFECTED_H
#endif
