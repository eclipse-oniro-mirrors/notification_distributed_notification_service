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

#include "notification_do_not_disturb_date.h"
#include "notificationdonotdisturbdate_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int64_t beginDate = 1;
        int64_t endDate = 3;
        uint32_t type = fdp->ConsumeIntegral<int32_t>();
        Notification::NotificationConstant::DoNotDisturbType disturbType =
            Notification::NotificationConstant::DoNotDisturbType(type);
        Notification::NotificationDoNotDisturbDate notificationDoNotDisturbDate(disturbType, beginDate, endDate);
        notificationDoNotDisturbDate.SetDoNotDisturbType(disturbType);
        notificationDoNotDisturbDate.GetDoNotDisturbType();
        notificationDoNotDisturbDate.SetBeginDate(beginDate);
        notificationDoNotDisturbDate.GetBeginDate();
        notificationDoNotDisturbDate.SetEndDate(endDate);
        notificationDoNotDisturbDate.Dump();
        return notificationDoNotDisturbDate.GetEndDate();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
