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
#include "notification_user_input.h"
#undef private
#undef protected
#include "notificationuserinputannex_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
        constexpr uint8_t INPUT_EDIT_TYPE = 3;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::NotificationUserInput notificationUserInput(stringData);
        AAFwk::Want want;
        Notification::NotificationUserInput userInput(stringData);
        std::map<std::string, std::shared_ptr<Uri>> results;
        notificationUserInput.AddMimeInputToWant(userInput, want, results);
        std::string inputKey(data);
        std::string tag(data);
        std::vector<std::string> options;
        options.emplace_back(stringData);
        bool permitFreeFormInput = *data % ENABLE;
        std::set<std::string> permitMimeTypes;
        std::shared_ptr<AAFwk::WantParams> additional;
        uint8_t inputEditTypes = *data % INPUT_EDIT_TYPE;
        Notification::NotificationConstant::InputEditType inputEditType =
            Notification::NotificationConstant::InputEditType(inputEditTypes);
        Notification::NotificationUserInput::Create(inputKey, tag, options, permitFreeFormInput,
            permitMimeTypes, additional, inputEditType);
        Notification::NotificationUserInput notificationUserInputannex
            (inputKey, tag, options, permitFreeFormInput, permitMimeTypes, additional, inputEditType);
        nlohmann::json jsonObject;
        notificationUserInputannex.ToJson(jsonObject);
        notificationUserInputannex.FromJson(jsonObject);
        Parcel parcel;
        return notificationUserInput.Marshalling(parcel);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
