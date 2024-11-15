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

#include "cancelgroup_fuzzer.h"
#include "ans_permission_def.h"
#include "notification_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        // test GetShowBadgeEnabled function
        bool enabled = fdp->ConsumeBool();
        Notification::NotificationHelper::GetShowBadgeEnabled(enabled);
        // test CancelGroup function
        std::string stringData = fdp->ConsumeRandomLengthString();
        Notification::NotificationHelper::CancelGroup(stringData);
        // test SetDoNotDisturbDate function
        uint32_t type = fdp->ConsumeIntegral<uint32_t>();
        Notification::NotificationDoNotDisturbDate disturb;
        Notification::NotificationConstant::DoNotDisturbType disturbType =
            Notification::NotificationConstant::DoNotDisturbType(type);
        disturb.SetDoNotDisturbType(disturbType);
        Notification::NotificationHelper::SetDoNotDisturbDate(disturb);
        // test GetDoNotDisturbDate function
        Notification::NotificationHelper::GetDoNotDisturbDate(disturb);
        // test DoesSupportDoNotDisturbMode function
        Notification::NotificationHelper::DoesSupportDoNotDisturbMode(enabled);
        // test IsDistributedEnabled function
        return Notification::NotificationHelper::IsDistributedEnabled(enabled);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
