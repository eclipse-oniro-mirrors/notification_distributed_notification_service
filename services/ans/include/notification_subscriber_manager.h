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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_SUBSCRIBER_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_SUBSCRIBER_MANAGER_H

#include <list>
#include <memory>
#include <mutex>

#include "errors.h"
#include "event_handler.h"
#include "event_runner.h"
#include "ffrt.h"
#include "nocopyable.h"
#include "refbase.h"
#include "singleton.h"

#include "enabled_priority_notification_by_bundle_callback_data.h"
#include "ians_subscriber.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_request.h"
#include "notification_sorting_map.h"
#include "notification_subscribe_info.h"

namespace OHOS {
namespace Notification {
class NotificationSubscriberManager : public DelayedSingleton<NotificationSubscriberManager> {
public:
    struct SubscriberRecord {
        sptr<IAnsSubscriber> subscriber {nullptr};
        std::set<std::string> bundleList_ {};
        std::set<int32_t> uidList_ {};
        bool subscribedAll {false};
        int32_t userId {SUBSCRIBE_USER_INIT};
        std::string deviceType {CURRENT_DEVICE_TYPE};
        int32_t subscriberUid {DEFAULT_UID};
        std::string subscriberBundleName_;
        bool needNotifyApplicationChanged = false;
        bool needNotifyResponse = false;
        uint32_t filterType {0};
        std::set<NotificationConstant::SlotType> slotTypes {};
        bool isSubscribeSelf = false;
        uint32_t subscribedFlags_ {0};
    };

    /**
     * @brief Add a subscriber.
     *
     * @param subscriber Indicates the AnsSubscriberInterface object.
     * @param subscribeInfo Indicates the NotificationSubscribeInfo object.
     * @param subscribedFlags Indicated the subscriber implemented method by bitset
     * @return Indicates the result code.
     */
    ErrCode AddSubscriber(const sptr<IAnsSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo, uint32_t subscribedFlags);

    /**
     * @brief Remove a subscriber.
     *
     * @param subscriber Indicates the AnsSubscriberInterface object.
     * @param subscribeInfo Indicates the NotificationSubscribeInfo object.
     * @return Indicates the result code.
     */
    ErrCode RemoveSubscriber(
        const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo);

    /**
     * @brief Notify all subscribers on counsumed.
     *
     * @param notification Indicates the Notification object.
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    void NotifyConsumed(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap);

    void BatchNotifyConsumed(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record);

    /**
     * @brief Notify all subscribers on canceled.
     *
     * @param notification Indicates the Notification object.
     * @param notificationMap Indicates the NotificationSortingMap object.
     * @param deleteReason Indicates the delete reason.
     */
    void NotifyCanceled(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);

    void BatchNotifyCanceled(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);
    /**
     * @brief Notify all subscribers on updated.
     *
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    void NotifyUpdated(const sptr<NotificationSortingMap> &notificationMap);

    /**
     * @brief Notify all subscribers on dnd date changed.
     *
     * @param userId Indicates which user need consume the update nofitication
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @param bundle Indicates which bundle need consume the update nofitication
     */
    void NotifyDoNotDisturbDateChanged(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date,
        const std::string &bundle);

    void NotifyEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData);

    /**
     * @brief Notify when the priority notification switch is changed.
     *
     * @param enable Indicates the switch state.
     * @param uid Indicates uid.
     */
    void NotifyEnabledPriorityChanged(const sptr<EnabledNotificationCallbackData> &callbackData);

    /**
     * @brief Notify when the priority notification switch by bundle is changed.
     *
     * @param callbackData Indicates the EnabledPriorityNotificationByBundleCallbackData object.
     */
    void NotifyEnabledPriorityByBundleChanged(
        const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData);

    /**
     * @brief Notify all subscribers on badge enabled state changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    void NotifyBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData);

    /**
     * @brief Obtains the death event.
     *
     * @param object Indicates the death object.
     */
    void OnRemoteDied(const wptr<IRemoteObject> &object);

    /**
     * @brief Set badge number.
     *
     * @param uid The application's uid.
     * @param bundleName The application's bundle name.
     * @param badgeNumber The badge number.
     */
    void SetBadgeNumber(const sptr<BadgeNumberCallbackData> &badgeData);

    /**
     * @brief Reset ffrt queue
     */
    void ResetFfrtQueue();

    /**
     * @brief Distribution operation based on hashCode.
     *
     * @param operationInfo Indicates the Notification params.
     * @param request Indicates the Notification request.
     */
    ErrCode DistributeOperation(
        const sptr<NotificationOperationInfo>& operationInfo, const sptr<NotificationRequest>& request);
 
    ErrCode DistributeOperationTask(const sptr<NotificationOperationInfo>& operationInfo,
        const sptr<NotificationRequest>& request, int32_t &funcResult);

    void RegisterOnSubscriberAddCallback(std::function<void(const std::shared_ptr<SubscriberRecord> &)> callback);

    void UnRegisterOnSubscriberAddCallback();

    std::list<std::shared_ptr<SubscriberRecord>> GetSubscriberRecords();

    void TrackCodeLog(const sptr<Notification> &notification);

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    bool GetIsEnableEffectedRemind();
    bool IsDeviceTypeSubscriberd(const std::string deviceType);
    ErrCode IsDeviceTypeAffordConsume(const std::string deviceType,
        const sptr<NotificationRequest> &request, bool &result);
#endif
    void NotifyApplicationInfoNeedChanged(const std::string& bundleName);

private:
    void NotifyApplicationInfochangedInner(const std::string& bundleName);
    std::shared_ptr<SubscriberRecord> FindSubscriberRecord(const wptr<IRemoteObject> &object);
    std::shared_ptr<SubscriberRecord> FindSubscriberRecord(const sptr<IAnsSubscriber> &subscriber);
    std::shared_ptr<SubscriberRecord> CreateSubscriberRecord(const sptr<IAnsSubscriber> &subscriber);
    void AddRecordInfo(
        std::shared_ptr<SubscriberRecord> &record, const sptr<NotificationSubscribeInfo> &subscribeInfo);
    void RemoveRecordInfo(
        std::shared_ptr<SubscriberRecord> &record, const sptr<NotificationSubscribeInfo> &subscribeInfo);
    ErrCode AddSubscriberInner(
        const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo);
    ErrCode RemoveSubscriberInner(
        const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo);

    void NotifyConsumedInner(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap);
    void BatchNotifyConsumedInner(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record);
    void NotifyCanceledInner(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);
    void BatchNotifyCanceledInner(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);
    void NotifyUpdatedInner(const sptr<NotificationSortingMap> &notificationMap);
    void NotifyDoNotDisturbDateChangedInner(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date,
        const std::string &bundle);
    void NotifyEnabledNotificationChangedInner(const sptr<EnabledNotificationCallbackData> &callbackData);
    void NotifyEnabledPriorityChangedInner(const sptr<EnabledNotificationCallbackData> &callbackData);
    void NotifyEnabledPriorityByBundleChangedInner(
        const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData);
    void NotifyBadgeEnabledChangedInner(const sptr<EnabledNotificationCallbackData> &callbackData);
    bool IsSystemUser(int32_t userId);
    bool IsSubscribedBysubscriber(
        const std::shared_ptr<SubscriberRecord> &record, const sptr<Notification> &notification);
    bool ConsumeRecordFilter(
        const std::shared_ptr<SubscriberRecord> &record, const sptr<Notification> &notification);
    bool IsNeedNotifySubscribers(const std::shared_ptr<SubscriberRecord> &record,
        const int32_t &userId, const std::string &bundle);
    bool IsNeedNotifySubscribers(const std::shared_ptr<SubscriberRecord> &record,
        int32_t userId, int32_t uid);
    bool IsNeedNotifySubscribers(const std::shared_ptr<SubscriberRecord> &record, int32_t userId);
    template <typename... Args>
    void NotifySubscribers(int32_t userId, int32_t uid, NotificationConstant::SubscribedFlag flags,
        ErrCode (IAnsSubscriber::*func)(Args...), Args&& ... args);
    template <typename... Args>
    void NotifySubscribers(int32_t userId, const std::string& bundle, NotificationConstant::SubscribedFlag flags,
        ErrCode (IAnsSubscriber::*func)(Args...), Args&& ... args);
    template <typename... Args>
    void NotifySubscribers(int32_t userId,
        NotificationConstant::SubscribedFlag flags, ErrCode (IAnsSubscriber::*func)(Args...), Args&& ... args);
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    bool IsDelayPriorityTargetSubscriber(
        const std::shared_ptr<SubscriberRecord> &subscriberRecord, const sptr<NotificationRequest> &request);
#endif

private:
    ffrt::mutex subscriberRecordListMutex_;
    std::list<std::shared_ptr<SubscriberRecord>> subscriberRecordList_ {};
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner_ {};
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_ {};
    sptr<IAnsSubscriber> ansSubscriberProxy_ {};
    sptr<IRemoteObject::DeathRecipient> recipient_ {};
    std::shared_ptr<ffrt::queue> notificationSubQueue_ = nullptr;
    std::function<void(const std::shared_ptr<SubscriberRecord> &)> onSubscriberAddCallback_ = nullptr;

    DECLARE_DELAYED_SINGLETON(NotificationSubscriberManager);
    DISALLOW_COPY_AND_MOVE(NotificationSubscriberManager);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_SUBSCRIBER_MANAGER_H
