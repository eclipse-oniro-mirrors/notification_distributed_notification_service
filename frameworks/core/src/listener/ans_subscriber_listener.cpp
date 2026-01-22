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

#include "ans_subscriber_listener.h"

#include "ans_trace_wrapper.h"
#include "notification_constant.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
SubscriberListener::SubscriberListener(const std::shared_ptr<NotificationSubscriber> &subscriber)
    : subscriber_(subscriber)
{};

SubscriberListener::~SubscriberListener()
{}

ErrCode SubscriberListener::OnConnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnConnected();
    return ERR_OK;
}

ErrCode SubscriberListener::OnDisconnected()
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnDisconnected();
    return ERR_OK;
}

ErrCode SubscriberListener::OnConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    if (notificationMap == nullptr) {
        ANS_LOGE("null notificationMap");
        return ERR_INVALID_DATA;
    }
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    subscriber->OnConsumed(sharedNotification, std::make_shared<NotificationSortingMap>(*notificationMap));
    return ERR_OK;
}

ErrCode SubscriberListener::OnConsumed(const sptr<Notification> &notification)
{
    return OnConsumed(notification, nullptr);
}

ErrCode SubscriberListener::OnConsumedList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    for (auto notification : notifications) {
        OnConsumed(notification, notificationMap);
    }
    return ERR_OK;
}

ErrCode SubscriberListener::OnConsumedList(const std::vector<sptr<Notification>> &notifications)
{
    return OnConsumedList(notifications, nullptr);
}

ErrCode SubscriberListener::OnCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    if (notificationMap == nullptr) {
        subscriber->OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(), deleteReason);
    } else {
        subscriber->OnCanceled(std::make_shared<Notification>(*notification),
            std::make_shared<NotificationSortingMap>(*notificationMap), deleteReason);
    }
    return ERR_OK;
}

ErrCode SubscriberListener::OnCanceled(const sptr<Notification> &notification, int32_t deleteReason)
{
    return OnCanceled(notification, nullptr, deleteReason);
}

void SubscriberListener::OnBatchCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
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

ErrCode SubscriberListener::OnCanceledList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    if (subscriber->HasOnBatchCancelCallback()) {
        OnBatchCanceled(notifications, notificationMap, deleteReason);
        return ERR_INVALID_DATA;
    }
    for (auto notification : notifications) {
        OnCanceled(notification, notificationMap, deleteReason);
    }
    return ERR_OK;
}

ErrCode SubscriberListener::OnCanceledList(
    const std::vector<sptr<Notification>> &notifications, int32_t deleteReason)
{
    return OnCanceledList(notifications, nullptr, deleteReason);
}

ErrCode SubscriberListener::OnUpdated(const sptr<NotificationSortingMap> &notificationMap)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnUpdate(std::make_shared<NotificationSortingMap>(*notificationMap));
    return ERR_OK;
}

ErrCode SubscriberListener::OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date)
{
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnDoNotDisturbDateChange(std::make_shared<NotificationDoNotDisturbDate>(*date));
    return ERR_OK;
}

ErrCode SubscriberListener::OnEnabledNotificationChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnEnabledNotificationChanged(std::make_shared<EnabledNotificationCallbackData>(*callbackData));
    return ERR_OK;
}

ErrCode SubscriberListener::OnEnabledPriorityChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnEnabledPriorityChanged(std::make_shared<EnabledNotificationCallbackData>(*callbackData));
    return ERR_OK;
}

ErrCode SubscriberListener::OnEnabledPriorityByBundleChanged(
    const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnEnabledPriorityByBundleChanged(
        std::make_shared<EnabledPriorityNotificationByBundleCallbackData>(*callbackData));
    return ERR_OK;
}

ErrCode SubscriberListener::OnEnabledWatchStatusChanged(uint32_t watchStatus)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnEnabledWatchStatusChanged(watchStatus);
    return ERR_OK;
}

ErrCode SubscriberListener::OnSystemUpdate(const sptr<Notification> &notification)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notification == nullptr) {
        ANS_LOGE("OnSystemUpdate fail, null notification");
        return ERR_INVALID_DATA;
    }
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnSystemUpdate(std::make_shared<Notification>(*notification));
    return ERR_OK;
}

ErrCode SubscriberListener::OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnBadgeChanged(std::make_shared<BadgeNumberCallbackData>(*badgeData));
    return ERR_OK;
}

ErrCode SubscriberListener::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnBadgeEnabledChanged(callbackData);
    return ERR_OK;
}

ErrCode SubscriberListener::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_INVALID_DATA;
    }
    subscriber->OnApplicationInfoNeedChanged(bundleName);
    return ERR_OK;
}

ErrCode SubscriberListener::OnOperationResponse(
    const sptr<NotificationOperationInfo>& operationInfo, int32_t& funcResult)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    auto subscriber = subscriber_.lock();
    if (subscriber == nullptr) {
        ANS_LOGW("null subscriber");
        return ERR_OK;
    }
    std::shared_ptr<NotificationOperationInfo> sharedNotification =
        std::make_shared<NotificationOperationInfo>(*operationInfo);
    funcResult = subscriber->OnOperationResponse(sharedNotification);
    return funcResult;
}
}  // namespace Notification
}  // namespace OHOS
