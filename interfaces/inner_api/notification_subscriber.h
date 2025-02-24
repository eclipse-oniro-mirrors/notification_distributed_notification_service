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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_H

#include "ans_manager_interface.h"
#include "ans_subscriber_stub.h"
#include "notification_request.h"
#include "notification_sorting.h"
#include "notification_sorting_map.h"

namespace OHOS {
namespace Notification {
class NotificationSubscriber : public std::enable_shared_from_this<NotificationSubscriber> {
public:
    NotificationSubscriber();

    virtual ~NotificationSubscriber();

    /**
     * @brief Called back when a notification is canceled.
     *
     * @param request Indicates the canceled Notification object.
     * @param sortingMap Indicates the sorting map used by the current subscriber
     * to obtain notification ranking information.
     * @param deleteReason Indicates the reason for the deletion. For details, see NotificationConstant.
     **/
    virtual void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) = 0;

    /**
     * @brief Called back when the subscriber is connected to the Advanced Notification Service (ANS).
     **/
    virtual void OnConnected() = 0;

    /**
     * @brief Called back when the subscriber receives a new notification.
     *
     * @param request Indicates the received Notification object.
     * @param sortingMap Indicates the sorting map used by the current subscriber to obtain
     * notification ranking information.
     **/
    virtual void OnConsumed(
        const std::shared_ptr<Notification> &request, const std::shared_ptr<NotificationSortingMap> &sortingMap) = 0;

    /**
     * @brief Called back when the subscriber is disconnected from the ANS.
     **/
    virtual void OnDisconnected() = 0;

    /**
     * @brief Called back when the ranking information about the current notification changes.
     *
     * @param sortingMap Indicates the sorting map used to obtain notification ranking information.
     **/
    virtual void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) = 0;

    /**
     * @brief Called back when connection to the ANS has died.
     **/
    virtual void OnDied() = 0;

    /**
     * @brief Called when the Do Not Disturb date changes.
     *
     * @param date Indicates the current Do Not Disturb date.
     **/
    virtual void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) = 0;

    /**
     * @brief Called when the notification permission changes.
     *
     * @param callbackData Indicates the properties of the application that notification permission has changed.
     **/
    virtual void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) = 0;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    virtual void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) = 0;

    /**
     * @brief The callback function on the badge enabled state changed.
     *
     * @param callbackData Indicates the properties of the application that badge enabled state has changed.
     */
    virtual void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) = 0;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    virtual void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) = 0;

    /**
     * @brief The callback function on the response.
     *
     * @param notification Indicates the received Notification object.
     */
    virtual ErrCode OnResponse(const std::shared_ptr<Notification> &notification)
    {
        return 0;
    }

    virtual bool HasOnBatchCancelCallback()
    {
        return false;
    }

    virtual void OnApplicationInfoNeedChanged(const std::string& bundleName)
    {
    }

    void SetDeviceType(const std::string &deviceType);

    std::string GetDeviceType() const;

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    bool ProcessSyncDecision(const std::string &deviceType, std::shared_ptr<Notification> &notification) const;
#endif

private:
    class SubscriberImpl final : public AnsSubscriberStub {
    public:
        class DeathRecipient final : public IRemoteObject::DeathRecipient {
        public:
            DeathRecipient(SubscriberImpl &subscriberImpl);

            ~DeathRecipient();

            void OnRemoteDied(const wptr<IRemoteObject> &object) override;

        private:
            SubscriberImpl &subscriberImpl_;
        };

    public:
        SubscriberImpl(NotificationSubscriber &subscriber);
        ~SubscriberImpl() {};

        void OnConnected() override;

        void OnDisconnected() override;

        void OnConsumed(
            const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) override;

        void OnConsumedList(const std::vector<sptr<Notification>> &notifications,
            const sptr<NotificationSortingMap> &notificationMap) override;

        void OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
            int32_t deleteReason) override;

        void OnCanceledList(const std::vector<sptr<Notification>> &notifications,
            const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override;

        void OnBatchCanceled(const std::vector<sptr<Notification>> &notifications,
            const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);

        void OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override;

        void OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override;

        void OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

        void OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override;

        void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

        void OnApplicationInfoNeedChanged(const std::string& bundleName) override;

        ErrCode OnResponse(const sptr<Notification> &notification) override;

        sptr<AnsManagerInterface> GetAnsManagerProxy();

    public:
        NotificationSubscriber &subscriber_;
        sptr<DeathRecipient> recipient_ {nullptr};
    };

private:
    const sptr<SubscriberImpl> GetImpl() const;
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    NotificationConstant::FlagStatus DowngradeReminder(
        const NotificationConstant::FlagStatus &oldFlags, const NotificationConstant::FlagStatus &judgeFlags) const;
#endif

private:
    sptr<SubscriberImpl> impl_ = nullptr;
    std::string deviceType_;

    friend class AnsNotification;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_H
