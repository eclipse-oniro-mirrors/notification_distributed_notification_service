/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATA_MANAGER_H
#define BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATA_MANAGER_H

#include <cstdint>

namespace OHOS::Notification {
class MockReminderDataManager {
public:
    static void MockPublishReminder(const int32_t ret);
    static void MockCancelReminder(const int32_t ret);
    static void MockCancelAllReminders(const int32_t ret);
    static void MockAddExcludeDate(const int32_t ret);
    static void MockDelExcludeDates(const int32_t ret);
    static void MockGetExcludeDates(const int32_t ret);
    static void MockQueryActiveReminderCount(const int32_t ret);
};
}  // namespace OHOS::Notification

#endif  // BASE_NOTIFICATION_REMINDER_MOCK_REMINDER_DATA_MANAGER_H