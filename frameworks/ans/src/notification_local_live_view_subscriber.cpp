/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "hitrace_meter_adapter.h"
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

void NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnConnected()
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->AddDeathRecipient(recipient_);
        ANS_LOGD("%s, Add death recipient.", __func__);
    }
    subscriber_.OnConnected();
}

void NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnDisconnected()
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (proxy != nullptr) {
        proxy->AsObject()->RemoveDeathRecipient(recipient_);
        ANS_LOGD("%s, Remove death recipient.", __func__);
    }
    subscriber_.OnDisconnected();
}

void NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::OnResponse(int32_t notificationId,
    sptr<NotificationButtonOption> buttonOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    subscriber_.OnResponse(notificationId, buttonOption);
}

sptr<AnsManagerInterface> NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl::GetAnsManagerProxy()
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

    sptr<AnsManagerInterface> proxy = iface_cast<AnsManagerInterface>(remoteObject);
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
