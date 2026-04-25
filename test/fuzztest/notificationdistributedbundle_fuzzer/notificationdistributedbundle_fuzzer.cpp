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
#include "notification_distributed_bundle.h"
#undef private
#undef protected
#include "notificationdistributedbundle_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t SWITCH_STATE_MAX = 4;

static void TestNotificationDistributedBundle(FuzzedDataProvider *fuzzData)
{
    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    int32_t uid = fuzzData->ConsumeIntegral<int32_t>();

    NotificationDistributedBundle bundle(bundleName, uid);
    bundle.GetBundleName();
    bundle.GetBundleUid();
    bundle.GetBundleLabel();
    bundle.GetBundleIcon();
    bundle.IsAncoBundle();
    bundle.GetAppIndex();
    bundle.CheckSameBundle();
    bundle.Dump();

    bundle.SetBundleName(fuzzData->ConsumeRandomLengthString());
    bundle.SetBundleUid(fuzzData->ConsumeIntegral<int32_t>());
    bundle.SetBundleLabel(fuzzData->ConsumeRandomLengthString());
    bundle.SetAncoBundle(fuzzData->ConsumeBool());
    bundle.SetAppIndex(fuzzData->ConsumeIntegral<int32_t>());

    std::string installedBundleName = fuzzData->ConsumeRandomLengthString();
    std::string installedLabel = fuzzData->ConsumeRandomLengthString();
    bundle.SetInstalledbundle(installedBundleName, installedLabel);
    bundle.CheckInstalledBundle(installedBundleName, installedLabel);

    uint8_t liveViewValue = fuzzData->ConsumeIntegral<uint8_t>() % SWITCH_STATE_MAX;
    uint8_t notificationValue = fuzzData->ConsumeIntegral<uint8_t>() % SWITCH_STATE_MAX;
    bundle.SetLiveViewEnable(static_cast<NotificationConstant::SWITCH_STATE>(liveViewValue));
    bundle.GetLiveViewEnable();
    bundle.SetNotificationEnable(static_cast<NotificationConstant::SWITCH_STATE>(notificationValue));
    bundle.GetNotificationEnable();

    Parcel parcel;
    bundle.Marshalling(parcel);
    NotificationDistributedBundle::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationDistributedBundle(fuzzData);
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
