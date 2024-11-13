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

#include "enabledistributed_fuzzer.h"

#include "notification_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        bool enabled = fdp->ConsumeBool();
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t usingData = fdp->ConsumeIntegral<int32_t>();

        // test EnableDistributed function
        Notification::NotificationHelper::EnableDistributed(enabled);
        // test EnableDistributedByBundle function
        Notification::NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(usingData);
        Notification::NotificationHelper::EnableDistributedByBundle(bundleOption, enabled);
        // test EnableDistributedSelf function
        Notification::NotificationHelper::EnableDistributedSelf(enabled);
        // test IsDistributedEnableByBundle function
        Notification::NotificationHelper::IsDistributedEnableByBundle(bundleOption, enabled);
        // test RemoveNotification function
        return Notification::NotificationHelper::RemoveNotification(bundleOption, usingData, stringData, usingData);
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
