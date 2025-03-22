/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_LOCAL_LIVE_VIEW_SUBSCRIBER_INTERFACE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_LOCAL_LIVE_VIEW_SUBSCRIBER_INTERFACE_H

#include "iremote_broker.h"

#include "badge_number_callback_data.h"
#include "enabled_notification_callback_data.h"
#include "notification.h"
#include "notification_constant.h"
#include "notification_do_not_disturb_date.h"
#include "notification_request.h"
#include "notification_sorting.h"
#include "notification_sorting_map.h"

namespace OHOS {
namespace Notification {
class AnsSubscriberLocalLiveViewInterface : public IRemoteBroker {
public:
    AnsSubscriberLocalLiveViewInterface() = default;
    virtual ~AnsSubscriberLocalLiveViewInterface() override = default;
    DISALLOW_COPY_AND_MOVE(AnsSubscriberLocalLiveViewInterface);

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.AnsSubscriberLocalLiveViewInterface");

    /**
     * @brief The callback function for the subscriber to establish a connection.
     */
    virtual void OnConnected() = 0;

    /**
     * @brief The callback function for subscriber disconnected.
     */
    virtual void OnDisconnected() = 0;

    virtual void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) = 0;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_LOCAL_LIVE_VIEW_SUBSCRIBER_INTERFACE_H
