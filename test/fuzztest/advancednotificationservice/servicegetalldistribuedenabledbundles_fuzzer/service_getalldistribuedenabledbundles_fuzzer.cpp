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
#include "service_getalldistribuedenabledbundles_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "advanced_notification_service.h"
#include "ans_permission_def.h"
#include "mock_notification_request.h"
#include "mock_notification_bundle_option.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service =  AdvancedNotificationService::GetInstance();
        service->InitPublishProcess();
        service->CreateDialogManager();
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        std::vector<NotificationBundleOption> bundelOptions;
        int32_t bundleNum = fuzzData->ConsumeIntegral<uint32_t>();
        for (int i = 0; i < bundleNum; i++) {
            NotificationBundleOption bundleOption = *(ObjectBuilder<NotificationBundleOption>::Build(fuzzData));
            bundelOptions.emplace_back(bundleOption);
        }
        service->GetAllDistribuedEnabledBundles(stringData, bundelOptions);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}