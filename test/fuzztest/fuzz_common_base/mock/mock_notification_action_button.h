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

#ifndef MOCK_NOTIFICATION_ACTION_BUTTON_BUILDER_H
#define MOCK_NOTIFICATION_ACTION_BUTTON_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_action_button.h"
#include "mock_notification_user_input.h"
#include "mock_pixel_map.h"

namespace OHOS {
namespace Notification {

template <>
std::shared_ptr<NotificationActionButton> ObjectBuilder<NotificationActionButton>::BuildSharedPtr(
    FuzzedDataProvider *fdp)
{
    std::string title = fdp->ConsumeRandomLengthString(50);
    auto icon = fdp->ConsumeBool() ? ObjectBuilder<Media::PixelMap>::BuildSharedPtr(fdp) : nullptr;

    auto semanticAction = static_cast<NotificationConstant::SemanticActionButton>(
        fdp->ConsumeIntegralInRange<uint8_t>(0, 3));
    bool autoReplies = fdp->ConsumeBool();
    std::vector<std::shared_ptr<NotificationUserInput>> mimeInputs;
    for (size_t i = 0; i < fdp->ConsumeIntegralInRange<size_t>(0, 5); ++i) {
        mimeInputs.push_back(ObjectBuilder<NotificationUserInput>::BuildSharedPtr(fdp));
    }
    auto userInput = fdp->ConsumeBool() ? ObjectBuilder<NotificationUserInput>::BuildSharedPtr(fdp) : nullptr;
    bool isContextual = fdp->ConsumeBool();

    ANS_LOGE("Build mock veriables");
    return NotificationActionButton::Create(
        icon, title, nullptr, nullptr, semanticAction, autoReplies, mimeInputs, userInput, isContextual);
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_ACTION_BUTTON_BUILDER_H
