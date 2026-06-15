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

#include "mock_reminder_datashare_helper.h"

#include "reminder_datashare_helper.h"

namespace OHOS::Notification {
static bool g_mockRegisterObserverRet = false;
static bool g_mockUnRegisterObserverRet = false;
static bool g_mockQueryRet = false;
static bool g_mockUpdateRet = false;
static bool g_mockDeleteRet = false;
static std::string g_mockQueryValue;
static std::map<std::string, sptr<ReminderRequest>> g_mockQueryReminders;

void MockReminderDatashareHelper::MockRegisterObserver(const bool ret)
{
    g_mockRegisterObserverRet = ret;
}

void MockReminderDatashareHelper::MockUnRegisterObserver(const bool ret)
{
    g_mockUnRegisterObserverRet = ret;
}

void MockReminderDatashareHelper::MockQuery(const bool ret, const std::string& value,
    const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    g_mockQueryRet = ret;
    g_mockQueryValue = value;
    g_mockQueryReminders = reminders;
}

void MockReminderDatashareHelper::MockUpdate(const bool ret)
{
    g_mockUpdateRet = ret;
}

ReminderDataShareHelper& ReminderDataShareHelper::GetInstance()
{
    static ReminderDataShareHelper helper;
    return helper;
}

bool ReminderDataShareHelper::RegisterObserver()
{
    return g_mockRegisterObserverRet;
}

bool ReminderDataShareHelper::UnRegisterObserver()
{
    return g_mockUnRegisterObserverRet;
}

bool ReminderDataShareHelper::Query(std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    reminders = g_mockQueryReminders;
    return g_mockQueryRet;
}

bool ReminderDataShareHelper::Query(Uri& uri, const std::string& key, std::string& value)
{
    value = g_mockQueryValue;
    return g_mockQueryRet;
}

bool ReminderDataShareHelper::Update(const std::string& identifier, const int32_t state)
{
    return g_mockUpdateRet;
}

void ReminderDataShareHelper::StartDataExtension(const int32_t reason)
{
}

void ReminderDataShareHelper::UpdateCalendarUid()
{
}

ReminderDataShareHelper::ReminderDataShareHelper()
{
}
}  // namespace OHOS::Notification