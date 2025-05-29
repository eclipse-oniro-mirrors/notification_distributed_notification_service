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

#ifndef MOCK_NOTIFICATION_LIVE_VIEW_CONTENT_BUILDER_H
#define MOCK_NOTIFICATION_LIVE_VIEW_CONTENT_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_live_view_content.h"

namespace OHOS {
namespace Notification {

template <>
NotificationLiveViewContent* ObjectBuilder<NotificationLiveViewContent>::Build(FuzzedDataProvider *fdp)
{
    auto content = new NotificationLiveViewContent();
    content->SetText(fdp->ConsumeRandomLengthString());
    content->SetTitle(fdp->ConsumeRandomLengthString());
    content->SetAdditionalText(fdp->ConsumeRandomLengthString());
    auto status = static_cast<NotificationLiveViewContent::LiveViewStatus>(fdp->ConsumeIntegralInRange<int>(0, 4));
    content->SetLiveViewStatus(status);
    content->SetVersion(fdp->ConsumeIntegral<uint32_t>());
    content->SetIsOnlyLocalUpdate(fdp->ConsumeBool());
    ANS_LOGE("Build mock veriables");
    return content;
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_LIVE_VIEW_CONTENT_BUILDER_H
