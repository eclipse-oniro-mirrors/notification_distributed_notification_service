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

#ifndef MOCK_NOTIFICATION_CONVERSATIONAL_CONTENT_BUILDER_H
#define MOCK_NOTIFICATION_CONVERSATIONAL_CONTENT_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_conversational_content.h"

namespace OHOS {
namespace Notification {

template <>
NotificationConversationalContent* ObjectBuilder<NotificationConversationalContent>::Build(FuzzedDataProvider *fdp)
{
    MessageUser user;
    user.SetKey(fdp->ConsumeRandomLengthString());
    user.SetName(fdp->ConsumeRandomLengthString());
    user.SetMachine(fdp->ConsumeBool());
    user.SetUserAsImportant(fdp->ConsumeBool());
    auto content = new NotificationConversationalContent(user);
    content->SetText(fdp->ConsumeRandomLengthString());
    content->SetTitle(fdp->ConsumeRandomLengthString());
    content->SetAdditionalText(fdp->ConsumeRandomLengthString());
    content->SetConversationTitle(fdp->ConsumeRandomLengthString(32));
    content->SetConversationGroup(fdp->ConsumeBool());
    content->AddConversationalMessage(fdp->ConsumeRandomLengthString(), fdp->ConsumeIntegral<int64_t>(), user);
    ANS_LOGE("Build mock veriables");
    return content;
}

} // namespace Notification
} // namespace OHOS

#endif // MOCK_NOTIFICATION_CONVERSATIONAL_CONTENT_BUILDER_H
