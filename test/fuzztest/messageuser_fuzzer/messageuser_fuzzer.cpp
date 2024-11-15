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
#include "message_user.h"
#undef private
#undef protected
#include "messageuser_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string key = fdp->ConsumeRandomLengthString();
        Notification::MessageUser messageUser;
        // test SetKey function
        messageUser.SetKey(key);
        // test SetName function
        std::string name = fdp->ConsumeRandomLengthString();
        messageUser.SetName(name);
        // test SetPixelMap function
        messageUser.SetPixelMap(nullptr);
        // test SetUri function
        Uri uri(key);
        messageUser.SetUri(uri);
        // test SetMachine function
        bool enabled = fdp->ConsumeBool();
        messageUser.SetMachine(enabled);
        // test SetUserAsImportant function
        messageUser.SetUserAsImportant(enabled);
        // test GetKey function
        messageUser.GetKey();
        // test GetName function
        messageUser.GetName();
        // test GetPixelMap function
        messageUser.GetPixelMap();
        // test GetUri function
        messageUser.GetUri();
        // test IsMachine function
        messageUser.IsMachine();
        // test IsUserImportant function
        messageUser.IsUserImportant();
        // test ToJson function
        nlohmann::json jsonObject;
        messageUser.ToJson(jsonObject);
        messageUser.FromJson(jsonObject);
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
