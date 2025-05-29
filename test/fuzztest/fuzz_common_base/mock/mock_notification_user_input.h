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

#ifndef MOCK_NOTIFICATION_USER_INPUT_BUILDER_H
#define MOCK_NOTIFICATION_USER_INPUT_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_user_input.h"
#include "mock_want_params.h"

namespace OHOS {
namespace Notification {

template <>
std::shared_ptr<NotificationUserInput> ObjectBuilder<NotificationUserInput>::BuildSharedPtr(FuzzedDataProvider *fdp)
{
    std::string inputKey = fdp->ConsumeRandomLengthString(20);
    std::string tag = fdp->ConsumeRandomLengthString(10);
    std::vector<std::string> options;
    for (size_t i = 0; i < fdp->ConsumeIntegralInRange<size_t>(0, 5); ++i) {
        options.push_back(fdp->ConsumeRandomLengthString(15));
    }
    bool permitFreeFormInput = fdp->ConsumeBool();
    std::set<std::string> permitMimeTypes;
    for (size_t i = 0; i < fdp->ConsumeIntegralInRange<size_t>(0, 3); ++i) {
        permitMimeTypes.insert(fdp->ConsumeRandomLengthString(10));
    }
    auto additional = ObjectBuilder<AAFwk::WantParams>::BuildSharedPtr(fdp);
    NotificationConstant::InputEditType editType = static_cast<NotificationConstant::InputEditType>(
        fdp->ConsumeIntegralInRange<int>(0, 2));

    ANS_LOGE("Build mock veriables");
    return NotificationUserInput::Create(inputKey, tag, options, permitFreeFormInput,
        permitMimeTypes, additional, editType);
}
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_USER_INPUT_BUILDER_H
