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
#include "service_publish_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "advanced_notification_service.h"
#include "ans_permission_def.h"
#include "mock_notification_request.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();

        service->InitPublishProcess();
        service->CreateDialogManager();
        std::string stringData = ConsumePrintableString(fuzzData, fuzzData->ConsumeIntegralInRange<int32_t>(0, 15));
        sptr<NotificationRequest> request = ObjectBuilder<NotificationRequest>::Build(fuzzData);
        service->Publish(stringData, request);
        if (request != nullptr) {
            uint64_t nums = 0;
            service->GetActiveNotificationNums(nums);
            // Cancel matches records by the request's own (bundle, uid, label, id),
            // so reusing its fields closes the publish -> query -> cancel chain
            service->Cancel(request->GetNotificationId(), request->GetLabel(),
                request->GetAppInstanceKey());
        }
        static const std::string kBoundaryLabels[] = {
            "",
            "boundary_label_overlong_" + std::string(256, 'x'),
            "\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c\xf0\x9f\x8e\x89",
            "%s%s%s%d%n\\\\..\\/..\\/",
        };
        sptr<NotificationRequest> boundaryRequest = ObjectBuilder<NotificationRequest>::Build(fuzzData);
        for (const std::string &label : kBoundaryLabels) {
            service->Publish(label, boundaryRequest);
        }
        uint64_t numsAfter = 0;
        service->GetActiveNotificationNums(numsAfter);
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
    ENSURE_ANS_SERVICE_CLEANED_AT_EXIT();
    return 0;
}
