/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "notification_live_view_content.h"
#include <string>
#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "advancednotificationservice_fuzzer.h"
#include "ans_subscriber_stub.h"
#include "ans_permission_def.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;
constexpr uint8_t ENABLE = 2;

namespace OHOS {
    

    bool DoSomethingInterestingWithMyAPI(FuzzData fuzzData)
    {
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data != nullptr && size >= GetU32Size()) {
        OHOS::FuzzData fuzzData(data, size);
        std::vector<std::string> requestPermission = {
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
        };
        SystemHapTokenGet(requestPermission);
        OHOS::DoSomethingInterestingWithMyAPI(fuzzData);
    }
    return 0;
}
