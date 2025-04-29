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
#include "notification_media_content.h"
#undef private
#undef protected
#include "notificationmediacontent_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        Notification::NotificationMediaContent notificationMediaContent;
        // test SetAVToken function
        std::shared_ptr<Notification::AVToken> avToken = nullptr;
        notificationMediaContent.SetAVToken(avToken);
        // test SetShownActions function
        std::vector<uint32_t> actions;
        notificationMediaContent.SetShownActions(actions);
        // test GetAVToken function
        notificationMediaContent.GetAVToken();
        // test GetShownActions function
        notificationMediaContent.GetShownActions();
        // test Dump function
        notificationMediaContent.Dump();
        // test Unmarshalling function
        Parcel parcel;
        notificationMediaContent.Unmarshalling(parcel);
        notificationMediaContent.ReadFromParcel(parcel);
        return notificationMediaContent.Marshalling(parcel);
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
