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

#include "reminder_request_factory.h"

#include "ans_log_wrapper.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"


#include <memory>
#include <thread>

namespace OHOS {
namespace Notification {
ReminderRequest* ReminderRequestFactory::CreateReminderRequest(ReminderRequest::ReminderType reminderType)
{
    ReminderRequest* reminderRequest = nullptr;
    switch (reminderType) {
        case (ReminderRequest::ReminderType::TIMER): {
            ANSR_LOGI("Create timer");
            reminderRequest = new (std::nothrow) ReminderRequestTimer();
            break;
        }
        case (ReminderRequest::ReminderType::ALARM): {
            ANSR_LOGI("Create alarm");
            reminderRequest = new (std::nothrow) ReminderRequestAlarm();
            break;
        }
        case (ReminderRequest::ReminderType::CALENDAR): {
            ANSR_LOGI("Create calendar");
            reminderRequest = new (std::nothrow) ReminderRequestCalendar();
            break;
        }
        default: {
            ANSR_LOGE("Create ReminderRequest fail.");
            return nullptr;
        }
    }
    if (reminderRequest == nullptr) {
        ANSR_LOGE("CreateReminderRequest fail.");
        return nullptr;
    }
    reminderRequest->SetReminderType(reminderType);
    return reminderRequest;
}

}  // namespace Notification
}  // namespace OHOS
