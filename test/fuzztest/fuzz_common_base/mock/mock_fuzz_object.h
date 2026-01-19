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

#ifndef MOCK_OBJECT_BUILDER_H
#define MOCK_OBJECT_BUILDER_H

#include "ans_log_wrapper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {
std::string ConsumePrintableString(FuzzedDataProvider *fdp, size_t size = 0) {
    if (size == 0) {
        size = fdp->ConsumeIntegral<size_t>();
    }
    std::string result;
    result.reserve(size);
    for (size_t i = 0; i < size; i++) {
        result += static_cast<char>(fdp->ConsumeIntegralInRange<uint32_t>(33, 126));
    }
    return result;
}
   
template <typename T>
struct ObjectBuilder {
    static T* Build(FuzzedDataProvider *fdp)
    {
        return nullptr;
    }

    static std::shared_ptr<T> BuildSharedPtr(FuzzedDataProvider *fdp)
    {
        return std::shared_ptr<T>(Build(fdp));
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_OBJECT_BUILDER_H
