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
#include "notification_conversational_content.h"
#undef private
#undef protected
#include "notificationconversationalcontent_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

#define DISABLE_FUZZ
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        Notification::MessageUser messageUser;
        Notification::NotificationConversationalContent NotificationConversationalContent(messageUser);
        NotificationConversationalContent.GetMessageUser();
        std::string stringData = fdp->ConsumeRandomLengthString();
        NotificationConversationalContent.SetConversationTitle(stringData);
        NotificationConversationalContent.GetConversationTitle();
        NotificationConversationalContent.IsConversationGroup();
        bool enabled = fdp->ConsumeBool();
        NotificationConversationalContent.SetConversationGroup(enabled);
        int64_t timestamp = 1;
        NotificationConversationalContent.AddConversationalMessage(stringData, timestamp, messageUser);
        Notification::NotificationConversationalContent::MessagePtr message;
        NotificationConversationalContent.AddConversationalMessage(message);
        NotificationConversationalContent.GetAllConversationalMessages();
        NotificationConversationalContent.Dump();
        Parcel parcel;
        NotificationConversationalContent.Marshalling(parcel);
        NotificationConversationalContent.Unmarshalling(parcel);
        return NotificationConversationalContent.ReadFromParcel(parcel);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
#ifndef DISABLE_FUZZ
        OHOS::DoSomethingInterestingWithMyAPI(&fdp);
#endif
    return 0;
}
