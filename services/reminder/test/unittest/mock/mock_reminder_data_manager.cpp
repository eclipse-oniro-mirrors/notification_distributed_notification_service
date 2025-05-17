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

#include "mock_reminder_data_manager.h"

#include "reminder_data_manager.h"

namespace OHOS::Notification {
namespace {
int32_t g_mockPublishReminderRet = 0;
int32_t g_mockUpdateReminderRet = 0;
int32_t g_mockCancelReminderRet = 0;
int32_t g_mockCancelAllRemindersRet = 0;
int32_t g_mockAddExcludeDateRet = 0;
int32_t g_mockDelExcludeDatesRet = 0;
int32_t g_mockGetExcludeDatesRet = 0;
int32_t g_mockQueryActiveReminderCountRet = 0;
}

void MockReminderDataManager::MockPublishReminder(const int32_t ret)
{
    g_mockPublishReminderRet = ret;
}

void MockReminderDataManager::MockUpdateReminder(const int32_t ret)
{
    g_mockUpdateReminderRet = ret;
}

void MockReminderDataManager::MockCancelReminder(const int32_t ret)
{
    g_mockCancelReminderRet = ret;
}

void MockReminderDataManager::MockCancelAllReminders(const int32_t ret)
{
    g_mockCancelAllRemindersRet = ret;
}

void MockReminderDataManager::MockAddExcludeDate(const int32_t ret)
{
    g_mockAddExcludeDateRet = ret;
}

void MockReminderDataManager::MockDelExcludeDates(const int32_t ret)
{
    g_mockDelExcludeDatesRet = ret;
}

void MockReminderDataManager::MockGetExcludeDates(const int32_t ret)
{
    g_mockGetExcludeDatesRet = ret;
}

void MockReminderDataManager::MockQueryActiveReminderCount(const int32_t ret)
{
    g_mockQueryActiveReminderCountRet = ret;
}

std::shared_ptr<ReminderDataManager> ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
ReminderDataManager::ReminderDataManager()
{}

ReminderDataManager::~ReminderDataManager()
{}

std::shared_ptr<ReminderDataManager> ReminderDataManager::GetInstance()
{
    return REMINDER_DATA_MANAGER;
}

std::shared_ptr<ReminderDataManager> ReminderDataManager::InitInstance()
{
    if (REMINDER_DATA_MANAGER == nullptr) {
        REMINDER_DATA_MANAGER = std::make_shared<ReminderDataManager>();
    }
    return REMINDER_DATA_MANAGER;
}

ErrCode ReminderDataManager::PublishReminder(const sptr<ReminderRequest>& reminder,
    const int32_t callingUid)
{
    return g_mockPublishReminderRet;
}

ErrCode ReminderDataManager::UpdateReminder(const sptr<ReminderRequest>& reminder,
    const int32_t callingUid)
{
    return g_mockUpdateReminderRet;
}

ErrCode ReminderDataManager::CancelReminder(const int32_t& reminderId, const int32_t callingUid)
{
    return g_mockCancelReminderRet;
}

ErrCode ReminderDataManager::CancelAllReminders(const std::string& packageName, const int32_t userId,
    const int32_t uid)
{
    return g_mockCancelAllRemindersRet;
}

void ReminderDataManager::GetValidReminders(const int32_t callingUid,
    std::vector<ReminderRequestAdaptation>& reminders)
{}

ErrCode ReminderDataManager::AddExcludeDate(const int32_t reminderId, const int64_t date,
    const int32_t callingUid)
{
    return g_mockAddExcludeDateRet;
}

ErrCode ReminderDataManager::DelExcludeDates(const int32_t reminderId, const int32_t callingUid)
{
    return g_mockDelExcludeDatesRet;
}

ErrCode ReminderDataManager::GetExcludeDates(const int32_t reminderId, const int32_t callingUid,
    std::vector<int64_t>& dates)
{
    return g_mockGetExcludeDatesRet;
}

int32_t ReminderDataManager::QueryActiveReminderCount()
{
    return g_mockQueryActiveReminderCountRet;
}
} // namespace OHOS::Notification