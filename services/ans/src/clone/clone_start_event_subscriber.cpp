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

#include "clone_start_event_subscriber.h"

#include "ans_log_wrapper.h"
#include "notification_clone_manager.h"

namespace OHOS {
namespace Notification {

const std::string CloneStartEventSubscriber::CLONE_EVENT_START = "usual.event.clone.startTransfer";

CloneStartEventSubscriber::CloneStartEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
}

CloneStartEventSubscriber::~CloneStartEventSubscriber()
{
    ANS_LOGD("called");
}

void CloneStartEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    ANS_LOGI("CloneStartEventSubscriber received event");
    NotificationCloneManager::GetInstance().OnRestoreEnd();
}

}  // namespace Notification
}  // namespace OHOS
