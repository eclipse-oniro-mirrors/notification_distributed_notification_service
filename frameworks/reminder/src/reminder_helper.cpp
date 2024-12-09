/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "reminder_helper.h"

#include "ans_log_wrapper.h"
#include "reminder_request_client.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
ErrCode ReminderHelper::PublishReminder(const ReminderRequest& reminder, int32_t& reminderId)
{
    ANSR_LOGI("PublishReminder start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->PublishReminder(reminder, reminderId);
}

ErrCode ReminderHelper::CancelReminder(const int32_t reminderId)
{
    ANSR_LOGI("CancelReminder start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->CancelReminder(reminderId);
}

ErrCode ReminderHelper::CancelAllReminders()
{
    ANSR_LOGI("CancelAllReminders start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->CancelAllReminders();
}

ErrCode ReminderHelper::GetValidReminders(std::vector<ReminderRequestAdaptation> &validReminders)
{
    ANSR_LOGI("GetValidReminders start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->GetValidReminders(validReminders);
}

ErrCode ReminderHelper::AddNotificationSlot(const NotificationSlot &slot)
{
    ANSR_LOGI("AddNotificationSlot start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->AddNotificationSlot(slot);
}

ErrCode ReminderHelper::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    ANSR_LOGI("RemoveNotificationSlot start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->RemoveNotificationSlot(slotType);
}

ErrCode ReminderHelper::AddExcludeDate(const int32_t reminderId, const int64_t date)
{
    ANSR_LOGI("AddExcludeDate start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->AddExcludeDate(reminderId, date);
}

ErrCode ReminderHelper::DelExcludeDates(const int32_t reminderId)
{
    ANSR_LOGI("DelExcludeDates start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->DelExcludeDates(reminderId);
}

ErrCode ReminderHelper::GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates)
{
    ANSR_LOGI("GetExcludeDates start");
    return DelayedSingleton<ReminderRequestClient>::GetInstance()->GetExcludeDates(reminderId, dates);
}

void ReminderHelper::StartReminderAgentService()
{
    ANSR_LOGI("StartReminderAgentService call");
    DelayedSingleton<ReminderRequestClient>::GetInstance()->StartReminderAgentService();
}
}
}