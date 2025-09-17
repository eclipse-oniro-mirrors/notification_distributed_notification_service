/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <thread>
#define private public

#include "notificationservice_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "notification_analytics_util.h"
#include "notification_request.h"
#include "notification_bundle_option.h"
#include "notification_live_view_content.h"
#include "advanced_notification_service.h"
#include "reminder_request_calendar.h"
#include "reminder_request.h"
#include "reminder_request_alarm.h"

namespace OHOS {
namespace Notification {

    bool TestNotificationService(FuzzedDataProvider *fdp)
    {
        int32_t id = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        auto service = AdvancedNotificationService::GetInstance();
        sptr<NotificationRequest> request = new NotificationRequest();
        std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
        std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
        liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        request->SetSlotType(slotType);
        request->SetContent(content);
        request->SetNotificationId(1);
        request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
        service->IsLiveViewCanRecover(nullptr);
        service->IsLiveViewCanRecover(request);
        return true;
    }

    bool TestReminderRequestCalendar(FuzzedDataProvider *fdp)
    {
        time_t now;
        (void)time(&now);
        struct tm nowTime;
        (void)localtime_r(&now, &nowTime);
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek;
        ReminderRequestCalendar calendar;
        ReminderRequestCalendar calendar2(calendar);

        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        calendar.DelExcludeDates();
        calendar.AddExcludeDate(static_cast<uint64_t>(now) * num);
        calendar.GetExcludeDates();
        calendar.IsInExcludeDate();
        calendar.GetRRuleWantAgentInfo();

        int32_t num2 = fdp->ConsumeIntegralInRange<uint32_t>(1, 100);
        int32_t num3 = fdp->ConsumeIntegralInRange<uint16_t>(1, 100);
        int32_t num4 = fdp->ConsumeIntegralInRange<uint8_t>(1, 100);
        int32_t num5 = fdp->ConsumeIntegralInRange<uint64_t>(1, 100);
        calendar.SetRepeatDay(num2);
        calendar.SetRepeatMonth(num3);
        calendar.SetRepeatMonth(num3);
        calendar.SetFirstDesignateYear(num3);
        calendar.SetFirstDesignageMonth(num3);
        calendar.SetFirstDesignateDay(num3);
        calendar.SetYear(num3);
        calendar.SetMonth(num4);
        calendar.SetDay(num4);
        calendar.SetHour(num4);
        calendar.SetMinute(num4);
        calendar.IsRepeat();
        calendar.CheckExcludeDate();
        calendar.IsNeedNotification();
        calendar.IsPullUpService();
        calendar.SetDateTime(num5);
        calendar.SetEndDateTime(num5);
        calendar.SetLastStartDateTime(num5);
        sptr<ReminderRequest> reminder1 = new ReminderRequestCalendar(num);
        calendar.Copy(reminder1);
        std::string str = fdp->ConsumeRandomLengthString();
        calendar.DeserializationRRule("");
        calendar.DeserializationRRule(str);
        calendar.DeserializationExcludeDates("");
        calendar.DeserializationExcludeDates(str);

        return true;
    }

    bool TestReminderRequest(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        int32_t num2 = fdp->ConsumeIntegralInRange<uint8_t>(1, 100);
        ReminderRequestAlarm alarm(num);
        ReminderRequestAlarm alarm2(alarm);
        alarm.SetHour(num2);
        alarm.SetMinute(num2);
        ReminderRequest reminderRequest(num);
        std::string str1 = "12.34";
        std::string str2 = "1";
        reminderRequest.StringToDouble(str1);
        reminderRequest.StringToInt(str2);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestNotificationService(fdp);
        TestReminderRequestCalendar(fdp);
        TestReminderRequest(fdp);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}