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
#include "reminder_request_timer.h"
#undef private
#undef protected
#include "reminderrequesttimer_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        uint64_t countDownTimeInSeconds = 0;
        std::string stringData(data);
        Notification::ReminderRequestTimer reminderRequestTimer(countDownTimeInSeconds);
        reminderRequestTimer.GetInitInfo();
        bool enabled = *data % ENABLE;
        reminderRequestTimer.PreGetNextTriggerTimeIgnoreSnooze(enabled, enabled);
        reminderRequestTimer.OnDateTimeChange();
        reminderRequestTimer.OnTimeZoneChange();
        reminderRequestTimer.UpdateNextReminder();
        reminderRequestTimer.CheckParamsValid(countDownTimeInSeconds);
        reminderRequestTimer.UpdateTimeInfo(stringData);
        Parcel parcel;
        reminderRequestTimer.Unmarshalling(parcel);
        reminderRequestTimer.Marshalling(parcel);
        return reminderRequestTimer.ReadFromParcel(parcel);
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
