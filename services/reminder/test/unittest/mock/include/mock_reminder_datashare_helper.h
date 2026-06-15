/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATASHARE_HELPER_H
#define BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATASHARE_HELPER_H

#include <map>
#include <string>

#include "reminder_request.h"

namespace OHOS::Notification {
class MockReminderDatashareHelper {
public:
    static void MockRegisterObserver(const bool ret);
    static void MockUnRegisterObserver(const bool ret);
    // value: Query(Uri&, const std::string&, std::string& value)
    // reminders: Query(std::map<std::string, sptr<ReminderRequest>>& reminders)
    static void MockQuery(const bool ret, const std::string& value,
        const std::map<std::string, sptr<ReminderRequest>>& reminders);
    static void MockUpdate(const bool ret);
};
}  // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATASHARE_HELPER_H
