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
#include "service_triggerupdateaiextnotification_fuzzer.h"

#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "advanced_notification_service.h"
#include "ans_permission_def.h"
#include "notification_classification.h"
#include "mock_notification_bundle_option.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();

        // Create NotificationRequest with fuzzed data
        sptr<NotificationRequest> request = new NotificationRequest();
        if (request == nullptr) {
            return false;
        }
        int32_t notificationId = fuzzData->ConsumeIntegral<int32_t>();
        request->SetNotificationId(notificationId);
        std::string label = fuzzData->ConsumeRandomLengthString();
        request->SetLabel(label);

        // Create NotificationClassification with fuzzed data
        std::string classification = fuzzData->ConsumeRandomLengthString();
        std::string subClassification = fuzzData->ConsumeRandomLengthString();
        sptr<NotificationClassification> notificationClassification =
            new NotificationClassification(classification, subClassification);
        if (notificationClassification == nullptr) {
            return false;
        }

        // Fill the priority triple with fuzzed values (TEST-03 / SEC-01): the parcel
        // path and the in process call reach the arbitration with arbitrary values, so
        // the fuzz inputs deliberately include the hostile shapes a malicious sender
        // could inject: an overlong or invalid type string (the type is an internal
        // channel value accepted as-is, the validation is owned by the third-party
        // entry NotificationRequest::SetPriorityNotificationType, so the landing and
        // the distribution must tolerate any string), an out of range source (the setter
        // validates the enum range) and a negative or INT64_MAX expire time (the
        // arbitration clamps the extremes beyond the max horizon, the schedule layer
        // treats a non positive time as undetermined and a past time as an immediate
        // degrade).
        // A dedicated selector slice keeps the extreme constants always present in the
        // exploration space (a plain ConsumeIntegral may randomly miss them).
        NotificationClassification::PriorityInfo priorityInfo;
        priorityInfo.SetPriorityNotificationType(fuzzData->ConsumeRandomLengthString());
        uint8_t expireSelector = fuzzData->ConsumeIntegral<uint8_t>();
        int64_t expiredTime = fuzzData->ConsumeIntegral<int64_t>();
        if (expireSelector & 0x01) {
            expiredTime = INT64_MAX;
        } else if (expireSelector & 0x02) {
            expiredTime = -1;
        }
        priorityInfo.SetExpiredTime(expiredTime);
        uint8_t sourceSelector = fuzzData->ConsumeIntegral<uint8_t>();
        int32_t source = fuzzData->ConsumeIntegral<int32_t>();
        if (sourceSelector & 0x01) {
            source = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD);
        } else if (sourceSelector & 0x02) {
            source = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT);
        } else if (sourceSelector & 0x04) {
            source = INT32_MAX;
        }
        priorityInfo.SetSource(source);
        // Dimension flag variant: a tagging round may carry only one dimension (a
        // priority rule refresh feeds back only the priority triple, an aggregation
        // reclassification may carry only the labels), and the dimensional landing
        // keeps the unset dimension of the cache instead of overwriting it with the
        // unset default. Randomly skip the priority setter so the priority-unset
        // variant stays in the exploration space.
        uint8_t prioritySetSelector = fuzzData->ConsumeIntegral<uint8_t>();
        if (prioritySetSelector & 0x01) {
            notificationClassification->SetPriorityInfo(priorityInfo);
        }

        // Null round variant: a tagging round with no result is a legal input shape
        // of this entry (the null round clears the cache entry and forces the
        // request type to OTHER), so keep it in the exploration space.
        uint8_t nullRoundSelector = fuzzData->ConsumeIntegral<uint8_t>();
        sptr<NotificationClassification> roundInput = notificationClassification;
        if (nullRoundSelector & 0x01) {
            roundInput = nullptr;
        }

        service->TriggerUpdateAiExtNotification(request, roundInput);
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
