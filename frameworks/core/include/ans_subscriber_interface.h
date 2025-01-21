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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_INTERFACE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_INTERFACE_H

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
class AnsSubscriberInterface : public IRemoteBroker {
public:
    AnsSubscriberInterface() = default;
    virtual ~AnsSubscriberInterface() override = default;
    DISALLOW_COPY_AND_MOVE(AnsSubscriberInterface);

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.AnsSubscriberInterface");

    /**
     * @brief The callback function for the subscriber to establish a connection.
     */
    virtual void OnConnected() = 0;

    /**
     * @brief The callback function for subscriber disconnected.
     */
    virtual void OnDisconnected() = 0;

    /**
     * @brief The callback function on a notification published.
     *
     * @param notification Indicates the consumed notification.
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    virtual void OnConsumed(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) = 0;

    virtual void OnConsumedList(
        const std::vector<sptr<Notification>> &notifications, const sptr<NotificationSortingMap> &notificationMap) = 0;

    /**
     * @brief The callback function on a notification canceled.
     *
     * @param notification Indicates the canceled notification.
     * @param notificationMap Indicates the NotificationSortingMap object.
     * @param deleteReason Indicates the delete reason.
     */
    virtual void OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) = 0;

    virtual void OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) = 0;

    /**
     * @brief The callback function on the notifications updated.
     *
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    virtual void OnUpdated(const sptr<NotificationSortingMap> &notificationMap) = 0;

    /**
     * @brief The callback function on the do not disturb date changed.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     */
    virtual void OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) = 0;

    /**
     * @brief The callback function on the notification enabled flag changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    virtual void OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) = 0;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    virtual void OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) = 0;

    /**
     * @brief The callback function on the badge enabled state changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    virtual void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) = 0;

    virtual void OnApplicationInfoNeedChanged(const std::string& bundleName) = 0;

    /**
     * @brief The callback function on the response.
     *
     * @param notification Indicates the received Notification object.
     */
    virtual ErrCode OnResponse(const sptr<Notification> &notification) = 0;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_INTERFACE_H
