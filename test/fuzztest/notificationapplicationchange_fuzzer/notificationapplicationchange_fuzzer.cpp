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
#include "notification_application_change_info.h"
#undef private
#undef protected
#include "notificationapplicationchange_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t CHANGE_TYPE_MAX = 4;

static void TestNotificationApplicationChangeInfo(FuzzedDataProvider *fuzzData)
{
    NotificationApplicationChangeInfo info;
    uint8_t changeTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % CHANGE_TYPE_MAX;
    info.SetChangeType(static_cast<DistributedBundleChangeType>(changeTypeValue));
    info.GetChangeType();

    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
    auto bundleOption = std::make_shared<NotificationBundleOption>(bundleName, uid);
    info.SetBundle(bundleOption);
    info.GetBundle();

    bool enable = fuzzData->ConsumeBool();
    info.SetEnable(enable);
    info.GetEnable();
    info.Dump();

    Parcel parcel;
    info.Marshalling(parcel);
    NotificationApplicationChangeInfo::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationApplicationChangeInfo(fuzzData);
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
