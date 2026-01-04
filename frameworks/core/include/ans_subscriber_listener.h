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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_SUBSCRIBER_LISTENER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_SUBSCRIBER_LISTENER_H

#include "ans_subscriber_stub.h"
#include "enabled_priority_notification_by_bundle_callback_data.h"
#include "ians_manager.h"
#include "notification_request.h"
#include "notification_sorting.h"
#include "notification_sorting_map.h"
#include "notification_subscriber.h"

namespace OHOS {
namespace Notification {
class SubscriberListener final : public AnsSubscriberStub {
public:
    SubscriberListener(const std::shared_ptr<NotificationSubscriber> &subscriber);
    ~SubscriberListener();

    ErrCode OnConnected() override;

    ErrCode OnDisconnected() override;

    ErrCode OnConsumed(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) override;

    ErrCode OnConsumed(const sptr<Notification> &notification) override;

    ErrCode OnConsumedWithMaxCapacity(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) override;

    ErrCode OnConsumedWithMaxCapacity(const sptr<Notification> &notification) override;

    ErrCode OnConsumedList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap) override;

    ErrCode OnConsumedList(const std::vector<sptr<Notification>> &notifications) override;

    ErrCode OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) override;

    ErrCode OnCanceled(const sptr<Notification> &notification, int32_t deleteReason) override;

    ErrCode OnCanceledWithMaxCapacity(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override;

    ErrCode OnCanceledWithMaxCapacity(const sptr<Notification> &notification, int32_t deleteReason) override;

    ErrCode OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override;

    ErrCode OnCanceledList(const std::vector<sptr<Notification>> &notifications, int32_t deleteReason) override;

    void OnBatchCanceled(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);

    ErrCode OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override;

    ErrCode OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override;

    ErrCode OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    ErrCode OnEnabledPriorityChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    ErrCode OnEnabledPriorityByBundleChanged(
        const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData) override;

    ErrCode OnEnabledWatchStatusChanged(uint32_t watchStatus) override;

    ErrCode OnSystemUpdate(const sptr<Notification> &notification) override;

    ErrCode OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override;

    ErrCode OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    ErrCode OnApplicationInfoNeedChanged(const std::string& bundleName) override;

    ErrCode OnOperationResponse(const sptr<NotificationOperationInfo>& operationInfo, int32_t& funcResult) override;

public:
    std::weak_ptr<NotificationSubscriber> subscriber_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_SUBSCRIBER_LISTENER_H
