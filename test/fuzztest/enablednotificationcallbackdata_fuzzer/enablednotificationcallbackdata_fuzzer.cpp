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
#include "enabled_notification_callback_data.h"
#undef private
#undef protected
#include "enablednotificationcallbackdata_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        uid_t uid = static_cast<int32_t>(GetU32Data(data));
        bool enabled = *data % ENABLE;
        Notification::EnabledNotificationCallbackData enabledNotificationCallbackData(stringData, uid, enabled);
        // test SetBundle function
        enabledNotificationCallbackData.SetBundle(stringData);
        // test SetUid function
        enabledNotificationCallbackData.SetUid(uid);
        // test SetEnable function
        enabledNotificationCallbackData.SetEnable(enabled);
        // test GetBundle function
        enabledNotificationCallbackData.GetBundle();
        // test GetUid function
        enabledNotificationCallbackData.GetUid();
        // test GetEnable function
        enabledNotificationCallbackData.GetEnable();
        // test Dump function
        enabledNotificationCallbackData.Dump();
        // test Unmarshalling function
        Parcel parcel;
        enabledNotificationCallbackData.Unmarshalling(parcel);
        enabledNotificationCallbackData.ReadFromParcel(parcel);
        return enabledNotificationCallbackData.Marshalling(parcel);
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
