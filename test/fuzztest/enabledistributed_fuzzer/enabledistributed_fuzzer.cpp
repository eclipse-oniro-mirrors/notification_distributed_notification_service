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

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        // test EnableDistributed function
        bool enabled = *data % ENABLE;
        Notification::NotificationHelper::EnableDistributed(enabled);
        // test EnableDistributedByBundle function
        std::string stringData(data);
        int32_t usingData = static_cast<int32_t>(GetU32Data(data));
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
    char *ch = ParseData(data, size);
    if (ch != nullptr && size > GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
