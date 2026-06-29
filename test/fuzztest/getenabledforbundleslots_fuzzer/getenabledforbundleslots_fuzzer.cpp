/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "getenabledforbundleslots_fuzzer.h"

#include "notification_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::vector<Notification::NotificationBundleOption> bundleOptions;
        size_t count = fdp->ConsumeIntegralInRange<size_t>(0, 5);
        for (size_t i = 0; i < count; i++) {
            Notification::NotificationBundleOption bundleOption;
            bundleOption.SetBundleName(fdp->ConsumeRandomLengthString());
            bundleOption.SetUid(fdp->ConsumeIntegral<int32_t>());
            bundleOptions.push_back(bundleOption);
        }
        int32_t slotTypeInt = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
        auto slotType = static_cast<Notification::NotificationConstant::SlotType>(slotTypeInt);
        std::map<sptr<Notification::NotificationBundleOption>, bool> slotEnabled;
        auto ret = Notification::NotificationHelper::GetEnabledForBundleSlots(
            bundleOptions, slotType, slotEnabled);
        return ret == ERR_OK;
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
