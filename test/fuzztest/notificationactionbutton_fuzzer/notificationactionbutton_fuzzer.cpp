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
#include "notification_action_button.h"
#undef private
#undef protected
#include "notificationactionbutton_fuzzer.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
            AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
        std::string title = fdp->ConsumeRandomLengthString();
        std::shared_ptr<Notification::NotificationActionButton> actionButton =
            Notification::NotificationActionButton::Create(nullptr, title, wantAgent);
        if (actionButton == nullptr) {
            return false;
        }
        // test AddAdditionalData function
        AAFwk::WantParams extras;
        actionButton->AddAdditionalData(extras);
        // test AddMimeTypeOnlyUserInput function
        std::shared_ptr<Notification::NotificationUserInput> userInput =
            std::make_shared<Notification::NotificationUserInput>();
        actionButton->AddMimeTypeOnlyUserInput(userInput);
        actionButton->AddNotificationUserInput(userInput);
        // test GetMimeTypeOnlyUserInputs function
        actionButton->GetMimeTypeOnlyUserInputs();
        // test GetUserInput function
        actionButton->GetUserInput();
        // test IsAutoCreatedReplies function
        actionButton->IsAutoCreatedReplies();
        return true;
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
