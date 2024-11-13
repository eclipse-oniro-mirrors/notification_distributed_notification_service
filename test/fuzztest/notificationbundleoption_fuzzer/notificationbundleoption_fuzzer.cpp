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
#include "notification_bundle_option.h"
#undef private
#undef protected
#include "notificationbundleoption_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string bundleNametitle = fdp->ConsumeRandomLengthString();
        int32_t uid = fdp->ConsumeIntegral<int32_t>();
        std::shared_ptr<Notification::NotificationBundleOption> notificationBundleOption =
        std::make_shared<Notification::NotificationBundleOption>(bundleNametitle, uid);
        // test GetUid function
        notificationBundleOption->GetUid();
        // test Dump function
        notificationBundleOption->Dump();
        // test Unmarshalling function
        Parcel parcel;
        notificationBundleOption->Unmarshalling(parcel);
        notificationBundleOption->ReadFromParcel(parcel);
        return notificationBundleOption->Marshalling(parcel);
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
