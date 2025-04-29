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
#include "notification_flags.h"
#undef private
#undef protected
#include "notificationflags_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        Notification::NotificationFlags notificationFlags;
        // test IsSoundEnabled function
        notificationFlags.IsSoundEnabled();
        // test IsVibrationEnabled function
        notificationFlags.IsVibrationEnabled();
        // test Dump function
        notificationFlags.Dump();
        // test ToJson function
        nlohmann::json jsonObject;
        if (jsonObject.is_null() or !jsonObject.is_object()) {
            return false;
        }
        notificationFlags.ToJson(jsonObject);
        notificationFlags.FromJson(jsonObject);
        // test Unmarshalling function
        Parcel parcel;
        notificationFlags.Unmarshalling(parcel);
        notificationFlags.ReadFromParcel(parcel);
        return true;
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
