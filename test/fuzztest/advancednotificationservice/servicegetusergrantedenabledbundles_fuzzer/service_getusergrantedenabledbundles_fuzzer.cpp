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

#include "service_getusergrantedenabledbundles_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "notification_helper.h"
#include "notification_bundle_option.h"
#include "ans_permission_def.h"
#include "mock_notification_request.h"
#include "advanced_notification_service.h"
#include "mock_notification_bundle_option.h"

namespace OHOS {
namespace Notification {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    sptr<NotificationBundleOption> targetBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);

    std::vector<sptr<NotificationBundleOption>> enabledBundles;

    ErrCode result = NotificationHelper::GetUserGrantedEnabledBundles(*targetBundle, enabledBundles);

    return true;
}

} // namespace Notification
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    
    constexpr int sleepMs = 100;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    
    return 0;
}