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

#ifndef MOCK_NOTIFICATION_CONTENT_BUILDER_H
#define MOCK_NOTIFICATION_CONTENT_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_content.h"
#include "mock_notification_conversational_content.h"
#include "mock_notification_media_content.h"
#include "mock_notification_live_view_content.h"
#include "mock_notification_multiline_content.h"
#include "mock_notification_normal_content.h"

namespace OHOS {
namespace Notification {

template <>
NotificationContent* ObjectBuilder<NotificationContent>::Build(FuzzedDataProvider *fdp)
{
    int caseNum = fdp->ConsumeIntegralInRange(0, 5);
    ANS_LOGE("Build mock veriables");
    switch (caseNum) {
        case 0:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationLiveViewContent>::Build(fdp));
        case 1:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationConversationalContent>::Build(fdp));
        case 2:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationMediaContent>::Build(fdp));
        case 3:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationMultiLineContent>::Build(fdp));
        case 4:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationNormalContent>::Build(fdp));
        default:
            return reinterpret_cast<NotificationContent*>(ObjectBuilder<NotificationLiveViewContent>::Build(fdp));
    }
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_CONTENT_BUILDER_H
