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

#include "notification_conversational_message.h"
#include "notificationconversationalmessage_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int64_t timestamp = 1;
        Notification::MessageUser sender;
        Notification::NotificationConversationalMessage notificationConversationalMessage(
            stringData, timestamp, sender);
        notificationConversationalMessage.GetText();
        notificationConversationalMessage.GetSender();
        notificationConversationalMessage.GetMimeType();
        notificationConversationalMessage.GetUri();
        return notificationConversationalMessage.GetArrivedTime();
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
