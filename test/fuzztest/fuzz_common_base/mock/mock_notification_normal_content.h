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

#ifndef MOCK_NOTIFICATION_NORMAL_CONTENT_BUILDER_H
#define MOCK_NOTIFICATION_NORMAL_CONTENT_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_normal_content.h"

namespace OHOS {
namespace Notification {

template <>
NotificationNormalContent* ObjectBuilder<NotificationNormalContent>::Build(FuzzedDataProvider *fdp)
{
    auto normalContent = new NotificationNormalContent();
    normalContent->SetText(fdp->ConsumeRandomLengthString());
    normalContent->SetTitle(fdp->ConsumeRandomLengthString());
    normalContent->SetAdditionalText(fdp->ConsumeRandomLengthString());
    ANS_LOGE("Build mock veriables");
    return normalContent;
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_NORMAL_CONTENT_BUILDER_H
