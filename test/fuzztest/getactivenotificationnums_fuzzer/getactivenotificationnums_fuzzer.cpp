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

#include "getactivenotificationnums_fuzzer.h"
#include "ans_permission_def.h"
#include "notification_helper.h"
namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        // test GetActiveNotificationNums function
        uint64_t num;
        Notification::NotificationHelper::GetActiveNotificationNums(num);
        std::string stringData(data);
        // test CanPublishNotificationAsBundle function
        bool enabled = *data % ENABLE;
        return Notification::NotificationHelper::CanPublishNotificationAsBundle(stringData, enabled);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        std::vector<std::string> requestPermission = {
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
        };
        SystemHapTokenGet(requestPermission);
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
