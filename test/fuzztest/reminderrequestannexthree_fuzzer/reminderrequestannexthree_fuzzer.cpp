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
#include "reminderrequestannexthree_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        Notification::ReminderRequest reminderRequest(reminderId);
        reminderRequest.GetTitle();
        uint64_t showTime = 2;
        reminderRequest.ReminderRequest::GetShowTime(showTime);
        Notification::ReminderRequest::TimeTransferType type = Notification::ReminderRequest::TimeTransferType::YEAR;
        int32_t cTime = static_cast<int32_t>(GetU32Data(data));
        reminderRequest.GetActualTime(type, cTime);
        reminderRequest.GetCTime(type, cTime);
        int32_t uid = static_cast<int32_t>(GetU32Data(data));
        reminderRequest.GetUserId(uid);
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
