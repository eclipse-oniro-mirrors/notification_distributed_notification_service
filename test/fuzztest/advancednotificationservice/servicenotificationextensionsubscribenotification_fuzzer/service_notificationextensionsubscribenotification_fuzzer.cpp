/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "service_notificationextensionsubscribenotification_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "advanced_notification_service.h"
#include "ans_permission_def.h"

namespace OHOS {
namespace Notification {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    auto service = AdvancedNotificationService::GetInstance();
    int32_t priorityStrategy = fuzzData->ConsumeIntegral<int32_t>();
    service->NotificationExtensionSubscribeNotification(priorityStrategy);
    return true;
}

} // namespace Notification
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission;
    if (fdp.ConsumeBool()) {
        requestPermission.emplace_back(OHOS::Notification::OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION);
    }
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    ENSURE_ANS_SERVICE_CLEANED_AT_EXIT();
    return 0;
}
