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

#include "notification_local_live_view_subscriber.h"

#include "ans_trace_wrapper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
NotificationLocalLiveViewSubscriber::NotificationLocalLiveViewSubscriber()
{
    impl_ = new (std::nothrow) SubscriberLocalLiveViewImpl(*this);
};

NotificationLocalLiveViewSubscriber::~NotificationLocalLiveViewSubscriber()
{}

const sptr<NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl> NotificationLocalLiveViewSubscriber::GetImpl() const
{
    return impl_;
}

NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::SubscriberLocalLiveViewImpl(
    NotificationLocalLiveViewSubscriber &subscriber) : subscriber_(subscriber)
{
    recipient_ = new (std::nothrow) DeathRecipient(*this);
};

ErrCode NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnConnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->AddDeathRecipient(recipient_);
        ANS_LOGD("Add death recipient");
    }
    subscriber_.OnConnected();
    return ERR_OK;
}

ErrCode NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnDisconnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->RemoveDeathRecipient(recipient_);
        ANS_LOGD("Remove death recipient");
    }
    subscriber_.OnDisconnected();
    return ERR_OK;
}

ErrCode NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnResponse(int32_t notificationId,
    const sptr<NotificationButtonOption> &buttonOption)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    subscriber_.OnResponse(notificationId, buttonOption);
    return ERR_OK;
}

sptr<IAnsManager> NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        return nullptr;
    }

    sptr<IAnsManager> proxy = iface_cast<IAnsManager>(remoteObject);
    if ((proxy == nullptr) || (proxy->AsObject() == nullptr)) {
        return nullptr;
    }

    return proxy;
}

NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::DeathRecipient::DeathRecipient(
    SubscriberLocalLiveViewImpl &subscriberImpl) : subscriberImpl_(subscriberImpl) {};

NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::DeathRecipient::~DeathRecipient() {};

void NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::DeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject> &object)
{
    subscriberImpl_.subscriber_.OnDied();
}
}  // namespace Notification
}  // namespace OHOS
