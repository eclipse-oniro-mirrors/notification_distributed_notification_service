/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public  // NOLINT
#define protected public  // NOLINT
#include "notification_voice_content.h"
#include "voice_content_option.h"
#undef private
#undef protected
#include "notificationvoicecontent_fuzzer.h"

#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

static void TestNotificationVoiceContent(FuzzedDataProvider *fuzzData)
{
    std::string textContent = fuzzData->ConsumeRandomLengthString();

    NotificationVoiceContent content;
    content.SetTextContent(textContent);
    content.GetTextContent();
    content.Dump();

    NotificationVoiceContent content2(content);
    Parcel parcel;
    if (!content2.Marshalling(parcel)) {
        return;
    }
    auto unmarshalledContent = std::unique_ptr<NotificationVoiceContent>(
        NotificationVoiceContent::Unmarshalling(parcel));
    if (unmarshalledContent != nullptr) {
        unmarshalledContent->Dump();
    }
}

static void TestVoiceContentOption(FuzzedDataProvider *fuzzData)
{
    bool enabled = fuzzData->ConsumeBool();

    VoiceContentOption option;
    option.SetEnabled(enabled);
    option.GetEnabled();

    VoiceContentOption option2(enabled);
    VoiceContentOption option3(option2);
    option3 = option2;

    Parcel parcel;
    if (!option3.Marshalling(parcel)) {
        return;
    }
    auto unmarshalledOption = std::unique_ptr<VoiceContentOption>(VoiceContentOption::Unmarshalling(parcel));
    if (unmarshalledOption != nullptr) {
        unmarshalledOption->GetEnabled();
    }
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationVoiceContent(fuzzData);
    TestVoiceContentOption(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}
