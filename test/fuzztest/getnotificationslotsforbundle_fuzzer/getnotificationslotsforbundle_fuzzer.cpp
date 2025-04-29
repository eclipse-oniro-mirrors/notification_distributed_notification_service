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

#include "getnotificationslotsforbundle_fuzzer.h"

#include "notification_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t usingData = fdp->ConsumeIntegral<int32_t>();
        Notification::NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(usingData);
        sptr<Notification::NotificationSlot> slot = nullptr;
        std::vector<sptr<Notification::NotificationSlot>> slots;
        slots.emplace_back(slot);
        // test UpdateNotificationSlots function
        Notification::NotificationHelper::UpdateNotificationSlots(bundleOption, slots);
        // test GetNotificationSlotsForBundle function
        Notification::NotificationHelper::GetNotificationSlotsForBundle(bundleOption, slots);
        // test RemoveGroupByBundle function
        return Notification::NotificationHelper::RemoveGroupByBundle(bundleOption, stringData);
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
