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

#include "notification_load_utils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "notification_load_utils.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string path = fdp->ConsumeRandomLengthString();
        NotificationLoadUtils utils(path);
        utils.IsValid();
        std::string funcName = fdp->ConsumeRandomLengthString();
        utils.GetProxyFunc(funcName);

        std::string otherPath = fdp->ConsumeRandomLengthString();
        NotificationLoadUtils otherUtils(otherPath);
        otherUtils.IsValid();
        otherUtils.GetProxyFunc(fdp->ConsumeRandomLengthString());

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
