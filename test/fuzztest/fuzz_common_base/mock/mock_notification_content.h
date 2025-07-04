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

const int INDEX_ZERO = 0;
const int INDEX_ONE = 1;
const int INDEX_TWO = 2;
const int INDEX_THREE = 3;

template <>
NotificationContent* ObjectBuilder<NotificationContent>::Build(FuzzedDataProvider *fdp)
{
    int caseNum = fdp->ConsumeIntegralInRange(0, 4);
    ANS_LOGE("Build mock veriables");
    switch (caseNum) {
        case INDEX_ZERO: {
            std::shared_ptr<NotificationConversationalContent> conversationalContent (
                ObjectBuilder<NotificationConversationalContent>::Build(fdp));
            return new NotificationContent(conversationalContent);
            break;
        }
        case INDEX_ONE: {
            std::shared_ptr<NotificationMediaContent> mediaContent (
                ObjectBuilder<NotificationMediaContent>::Build(fdp));
            return new NotificationContent(mediaContent);
            break;
        }
        case INDEX_TWO: {
            std::shared_ptr<NotificationMultiLineContent> multiContent (
                ObjectBuilder<NotificationMultiLineContent>::Build(fdp));
            return new NotificationContent(multiContent);
            break;
        }
        case INDEX_THREE: {
            std::shared_ptr<NotificationNormalContent> normalContent (
                ObjectBuilder<NotificationNormalContent>::Build(fdp));
            return new NotificationContent(normalContent);
            break;
        }
        default: {
            std::shared_ptr<NotificationNormalContent> defaultNormalContent (
                ObjectBuilder<NotificationNormalContent>::Build(fdp));
            return new NotificationContent(defaultNormalContent);
            break;
        }
    }
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_CONTENT_BUILDER_H
