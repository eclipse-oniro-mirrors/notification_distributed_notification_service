/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "ans_subscriber_listener.h"
#include "notification_constant.h"
#include "hitrace_meter_adapter.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
SubscriberListener::SubscriberListener(const std::shared_ptr<NotificationSubscriber> &subscriber)
    : subscriber_(subscriber)
{};

SubscriberListener::~SubscriberListener()
{}

void SubscriberListener::OnConnected()
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnConnected();
}

void SubscriberListener::OnDisconnected()
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnDisconnected();
}

void SubscriberListener::OnConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }

    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    if (!subscriber->ProcessSyncDecision(subscriber->GetDeviceType(), sharedNotification)) {
        return;
    }
#endif

    subscriber->OnConsumed(
        sharedNotification, std::make_shared<NotificationSortingMap>(*notificationMap));
}

void SubscriberListener::OnConsumedList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    for (auto notification : notifications) {
        OnConsumed(notification, notificationMap);
    }
}

void SubscriberListener::OnCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    if (notificationMap == nullptr) {
        subscriber->OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(), deleteReason);
    } else {
        subscriber->OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(*notificationMap), deleteReason);
    }
}

void SubscriberListener::OnBatchCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    std::vector<std::shared_ptr<Notification>> notificationList;
    for (auto notification : notifications) {
        notificationList.emplace_back(std::make_shared<Notification>(*notification));
    }
    if (notificationMap == nullptr) {
        subscriber->OnBatchCanceled(notificationList,
            std::make_shared<NotificationSortingMap>(), deleteReason);
    } else {
        subscriber->OnBatchCanceled(notificationList,
            std::make_shared<NotificationSortingMap>(*notificationMap), deleteReason);
    }
}

void SubscriberListener::OnCanceledList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    if (subscriber->HasOnBatchCancelCallback()) {
        OnBatchCanceled(notifications, notificationMap, deleteReason);
        return;
    }
    for (auto notification : notifications) {
        OnCanceled(notification, notificationMap, deleteReason);
    }
}

void SubscriberListener::OnUpdated(const sptr<NotificationSortingMap> &notificationMap)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnUpdate(std::make_shared<NotificationSortingMap>(*notificationMap));
}

void SubscriberListener::OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnDoNotDisturbDateChange(std::make_shared<NotificationDoNotDisturbDate>(*date));
}

void SubscriberListener::OnEnabledNotificationChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnEnabledNotificationChanged(std::make_shared<EnabledNotificationCallbackData>(*callbackData));
}

void SubscriberListener::OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnBadgeChanged(std::make_shared<BadgeNumberCallbackData>(*badgeData));
}

void SubscriberListener::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnBadgeEnabledChanged(callbackData);
}

void SubscriberListener::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGE("OnApplicationInfoNeedChanged  SubscriberListener 1.");
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("Subscriber is nullptr");
        return;
    }
    subscriber->OnApplicationInfoNeedChanged(bundleName);
}
}  // namespace Notification
}  // namespace OHOS
