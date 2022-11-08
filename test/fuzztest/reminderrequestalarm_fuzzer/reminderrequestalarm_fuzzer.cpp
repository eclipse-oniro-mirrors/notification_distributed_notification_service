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
#include "reminder_request_alarm.h"
#undef private
#undef protected
#include "reminderrequestalarm_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t HOUR = 24;
        constexpr uint8_t MINUTE = 60;
        constexpr uint8_t WEEK = 7;
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        uint8_t hour = *data % HOUR;
        uint8_t minute = *data % MINUTE;
        uint8_t week = *data % WEEK;
        std::vector<uint8_t> daysOfWeek;
        daysOfWeek.push_back(week);
        auto rrc = std::make_shared<Notification::ReminderRequestAlarm>(hour, minute, daysOfWeek);
        // test SetDaysOfWeek function
        bool enabled = *data % ENABLE;
        rrc->SetDaysOfWeek(enabled, daysOfWeek);
        // test GetDaysOfWeek function
        rrc->GetDaysOfWeek();
        // test CheckParamValid function
        rrc->CheckParamValid();
        // test IsRepeatReminder function
        rrc->IsRepeatReminder();
        // test PreGetNextTriggerTimeIgnoreSnooze function
        rrc->PreGetNextTriggerTimeIgnoreSnooze(enabled, enabled);
        // test GetNextTriggerTime function
        rrc->GetNextTriggerTime(enabled);
        // test GetNextAlarm function
        time_t now;
        (void)time(&now);  // unit is seconds.
        time_t target = *data % ENABLE;
        rrc->GetNextAlarm(now, target);
        // test IsRepeatDay function
        int32_t day = static_cast<int32_t>(GetU32Data(data));
        rrc->IsRepeatDay(day);
        // test GetHour function
        rrc->GetHour();
        // test GetMinute function
        rrc->GetMinute();
        // test GetRepeatDay function
        rrc->GetRepeatDay();
        // test OnDateTimeChange function
        rrc->OnDateTimeChange();
        // test OnTimeZoneChange function
        rrc->OnTimeZoneChange();
        // test UpdateNextReminder function
        rrc->UpdateNextReminder();
        // test Unmarshalling function
        Parcel parcel;
        rrc->Unmarshalling(parcel);
        rrc->ReadFromParcel(parcel);
        // test RecoverFromDb function
        std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet =
        std::make_shared<NativeRdb::AbsSharedResultSet>();
        rrc->RecoverFromDb(resultSet);
        return rrc->Marshalling(parcel);
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
