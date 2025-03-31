/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef BND_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_H
#define BND_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_H

#include "ans_manager_interface.h"
#include "ans_subscriber_stub.h"
#include "ans_subscriber_local_live_view_stub.h"
#include "notification_request.h"
#include "notification_sorting.h"
#include "notification_sorting_map.h"

namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewSubscriber {
public:
    NotificationLocalLiveViewSubscriber();

    virtual ~NotificationLocalLiveViewSubscriber();

    /**
     * @brief Called back when the subscriber is connected to the Advanced Notification Service (ANS).
     **/
    virtual void OnConnected() = 0;

    /**
     * @brief Called back when the subscriber is disconnected from the ANS.
     **/
    virtual void OnDisconnected() = 0;

    virtual void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) = 0;

    /**
     * @brief Called back when connection to the ANS has died.
     **/
    virtual void OnDied() = 0;

private:
    class SubscriberLocalLiveViewImpl final : public AnsSubscriberLocalLiveViewStub {
    public:
        class DeathRecipient final : public IRemoteObject::DeathRecipient {
        public:
            DeathRecipient(SubscriberLocalLiveViewImpl &subscriberImpl);

            ~DeathRecipient();

            void OnRemoteDied(const wptr<IRemoteObject> &object) override;

        private:
            SubscriberLocalLiveViewImpl &subscriberImpl_;
        };

    public:
        SubscriberLocalLiveViewImpl(NotificationLocalLiveViewSubscriber &subscriber);
        ~SubscriberLocalLiveViewImpl() {};

        ErrCode OnConnected() override;

        ErrCode OnDisconnected() override;

        ErrCode OnResponse(int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption) override;

        sptr<AnsManagerInterface> GetAnsManagerProxy();

    public:
        NotificationLocalLiveViewSubscriber &subscriber_;
        sptr<DeathRecipient> recipient_ {nullptr};
    };

private:
    const sptr<SubscriberLocalLiveViewImpl> GetImpl() const;

private:
    sptr<SubscriberLocalLiveViewImpl> impl_ = nullptr;

    friend class AnsNotification;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BND_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_H