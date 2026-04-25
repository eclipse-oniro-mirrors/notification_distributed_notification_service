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
#include "notification_statistics.h"
#undef private
#undef protected
#include "notificationstatistics_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

static void TestNotificationStatistics(FuzzedDataProvider *fuzzData)
{
    NotificationStatistics statistics;
    int64_t lastTime = fuzzData->ConsumeIntegral<int64_t>();
    int32_t recentCount = fuzzData->ConsumeIntegral<int32_t>();

    statistics.SetLastTime(lastTime);
    statistics.GetLastTime();
    statistics.SetRecentCount(recentCount);
    statistics.GetRecentCount();

    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
    NotificationBundleOption bundleOption(bundleName, uid);
    statistics.SetBundleOption(bundleOption);
    statistics.GetBundleOption();
    statistics.Dump();

    nlohmann::json jsonObject;
    statistics.ToJson(jsonObject);
    NotificationStatistics::FromJson(jsonObject);

    Parcel parcel;
    statistics.Marshalling(parcel);
    NotificationStatistics::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationStatistics(fuzzData);
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
