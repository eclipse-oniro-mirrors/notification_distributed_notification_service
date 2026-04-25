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

#define private public
#define protected public
#include "notification_unified_group_Info.h"
#undef private
#undef protected
#include "notificationunifiedgroup_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

static void TestNotificationUnifiedGroupInfo(FuzzedDataProvider *fuzzData)
{
    NotificationUnifiedGroupInfo info;
    std::string key = fuzzData->ConsumeRandomLengthString();
    std::string title = fuzzData->ConsumeRandomLengthString();
    std::string content = fuzzData->ConsumeRandomLengthString();
    std::string sceneName = fuzzData->ConsumeRandomLengthString();

    info.SetKey(key);
    info.GetKey();
    info.SetTitle(title);
    info.GetTitle();
    info.SetContent(content);
    info.GetContent();
    info.SetSceneName(sceneName);
    info.GetSceneName();
    info.GetExtraInfo();
    info.Dump();

    Parcel parcel;
    info.Marshalling(parcel);
    NotificationUnifiedGroupInfo::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationUnifiedGroupInfo(fuzzData);
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
