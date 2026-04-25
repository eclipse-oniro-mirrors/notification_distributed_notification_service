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
#include "notification_ringtone_info.h"
#undef private
#undef protected
#include "notificationringtone_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t RINGTONE_TYPE_MAX = 3;

static void TestNotificationRingtoneInfo(FuzzedDataProvider *fuzzData)
{
    uint8_t ringtoneTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % RINGTONE_TYPE_MAX;
    NotificationConstant::RingtoneType ringtoneType =
        static_cast<NotificationConstant::RingtoneType>(ringtoneTypeValue);
    std::string ringtoneTitle = fuzzData->ConsumeRandomLengthString();
    std::string ringtoneFileName = fuzzData->ConsumeRandomLengthString();
    std::string ringtoneUri = fuzzData->ConsumeRandomLengthString();

    NotificationRingtoneInfo info(ringtoneType, ringtoneTitle, ringtoneFileName, ringtoneUri);
    info.GetRingtoneType();
    info.GetRingtoneTitle();
    info.GetRingtoneFileName();
    info.GetRingtoneUri();
    info.Dump();

    NotificationRingtoneInfo info2;
    info2.SetRingtoneType(ringtoneType);
    info2.SetRingtoneTitle(ringtoneTitle);
    info2.SetRingtoneFileName(ringtoneFileName);
    info2.SetRingtoneUri(ringtoneUri);
    info2.ResetRingtone();

    std::string jsonStr = info2.ToJson();
    info2.FromJson(jsonStr);

    Parcel parcel;
    info2.Marshalling(parcel);
    NotificationRingtoneInfo::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationRingtoneInfo(fuzzData);
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
