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

#define private public
#define protected public
#include "notification_switch_changed_callback_data.h"
#undef private
#undef protected

#include "notificationswitchchangedcallbackdata_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string switchName = fdp->ConsumeRandomLengthString();
        int32_t userId = fdp->ConsumeIntegral<int32_t>();

        // Test all SWITCH_STATE values
        NotificationConstant::SWITCH_STATE enableStatus =
            static_cast<NotificationConstant::SWITCH_STATE>(fdp->ConsumeIntegralInRange<int32_t>(0, 3));

        // Test constructor with parameters
        NotificationSwitchChangedCallbackData callbackData(switchName, userId, enableStatus);

        // Test SetUserId/GetUserId
        int32_t newUserId = fdp->ConsumeIntegral<int32_t>();
        callbackData.SetUserId(newUserId);
        callbackData.GetUserId();

        // Test SetSwitchName/GetSwitchName
        std::string newSwitchName = fdp->ConsumeRandomLengthString();
        callbackData.SetSwitchName(newSwitchName);
        callbackData.GetSwitchName();

        // Test SetEnableStatus/GetEnableStatus with all SWITCH_STATE values
        NotificationConstant::SWITCH_STATE states[] = {
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF,
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON,
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF,
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON
        };
        for (auto state : states) {
            callbackData.SetEnableStatus(state);
            callbackData.GetEnableStatus();
        }

        // Test Dump
        callbackData.Dump();

        // Test Marshalling/Unmarshalling
        Parcel parcel;
        callbackData.Marshalling(parcel);
        NotificationSwitchChangedCallbackData::Unmarshalling(parcel);

        // Test default constructor
        NotificationSwitchChangedCallbackData defaultData;
        defaultData.SetUserId(fdp->ConsumeIntegral<int32_t>());
        defaultData.SetSwitchName(fdp->ConsumeRandomLengthString());
        NotificationConstant::SWITCH_STATE randomState =
            static_cast<NotificationConstant::SWITCH_STATE>(fdp->ConsumeIntegralInRange<int32_t>(0, 3));
        defaultData.SetEnableStatus(randomState);
        defaultData.GetUserId();
        defaultData.GetSwitchName();
        defaultData.GetEnableStatus();
        defaultData.Dump();

        Parcel parcel2;
        defaultData.Marshalling(parcel2);
        NotificationSwitchChangedCallbackData::Unmarshalling(parcel2);

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
    return 0;
}