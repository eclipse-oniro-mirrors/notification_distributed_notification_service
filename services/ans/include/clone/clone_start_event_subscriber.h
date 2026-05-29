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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_START_EVENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_START_EVENT_H

#include <memory>
#include <string>

#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"

namespace OHOS {
namespace Notification {

class CloneStartEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    static const std::string CLONE_EVENT_START;

    explicit CloneStartEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    ~CloneStartEventSubscriber() override;

    /**
     * @brief Obtains the clone start event. Inherited from EventFwk::CommonEventSubscriber.
     *
     * @param data Indicates the EventFwk::CommonEventData object.
     */
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    DISALLOW_COPY_AND_MOVE(CloneStartEventSubscriber);
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_CLONE_START_EVENT_H
