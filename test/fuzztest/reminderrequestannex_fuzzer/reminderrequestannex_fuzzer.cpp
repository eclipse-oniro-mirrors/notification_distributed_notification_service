/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "reminder_request.h"
#undef private
#undef protected
#include "reminderrequestannex_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        Notification::ReminderRequest reminderRequest(reminderId);
        reminderRequest.SetSnoozeTimes(*data);
        reminderRequest.SetSnoozeTimesDynamic(*data);
        uint64_t timeIntervalInSeconds = 1;
        reminderRequest.SetTimeInterval(timeIntervalInSeconds);
        reminderRequest.SetTitle(stringData);
        reminderRequest.SetTriggerTimeInMilli(timeIntervalInSeconds);
        std::shared_ptr< Notification::ReminderRequest::WantAgentInfo> wantAgentInfo =
            std::make_shared< Notification::ReminderRequest::WantAgentInfo>();
        reminderRequest.SetWantAgentInfo(wantAgentInfo);
        reminderRequest.ShouldShowImmediately();
        reminderRequest.GetActionButtons();
        reminderRequest.GetContent();
        reminderRequest.GetExpiredContent();
        reminderRequest.GetMaxScreenWantAgentInfo();
        reminderRequest.GetNotificationId();
        reminderRequest.GetNotificationRequest();
        reminderRequest.GetReminderId();
        reminderRequest.GetReminderTimeInMilli();
        reminderRequest.SetReminderId(reminderId);
        reminderRequest.SetReminderTimeInMilli(timeIntervalInSeconds);
        uint64_t ringDurationInSeconds = 0;
        reminderRequest.SetRingDuration(ringDurationInSeconds);
        reminderRequest.GetSlotType();
        reminderRequest.GetSnoozeContent();
        reminderRequest.GetSnoozeTimes();
        reminderRequest.GetSnoozeTimesDynamic();
        reminderRequest.GetState();
        reminderRequest.GetTimeInterval();
        reminderRequest.GetTriggerTimeInMilli();
        reminderRequest.GetUserId();
        reminderRequest.GetUid();
        reminderRequest.GetWantAgentInfo();
        reminderRequest.GetReminderType();
        reminderRequest.GetRingDuration();
        reminderRequest.UpdateNextReminder();
        reminderRequest.SetNextTriggerTime();
        Parcel parcel;
        reminderRequest.Marshalling(parcel);
        reminderRequest.Unmarshalling(parcel);
        reminderRequest.ReadFromParcel(parcel);
        reminderRequest.InitNotificationRequest();
        reminderRequest.InitServerObj();
        return reminderRequest.IsAlerting();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
