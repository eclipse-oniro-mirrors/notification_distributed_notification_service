/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H

#include "common_event_subscriber.h"
#include "reminder_data_manager.h"
#include "system_ability_status_change_stub.h"
#include "notification_subscriber.h"

#include <memory>

namespace OHOS {
namespace Notification {
class ReminderEventManager {
public:
    explicit ReminderEventManager(std::shared_ptr<ReminderDataManager> &reminderDataManager);
    virtual ~ReminderEventManager() {};
    ReminderEventManager(ReminderEventManager &other) = delete;
    ReminderEventManager& operator = (const ReminderEventManager &other) = delete;

private:
    void init(std::shared_ptr<ReminderDataManager> &reminderDataManager) const;
    void SubscribeSystemAbility(std::shared_ptr<ReminderDataManager> &reminderDataManager) const;

class ReminderEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ReminderEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
        std::shared_ptr<ReminderDataManager> &reminderDataManager);
    virtual void OnReceiveEvent(const EventFwk::CommonEventData &data);

private:
    sptr<NotificationBundleOption> GetBundleOption(const OHOS::EventFwk::Want &want) const;
    int32_t GetUid(const OHOS::EventFwk::Want &want) const;
    void HandlePackageRemove(const EventFwk::Want &want) const;
    void HandleProcessDied(const EventFwk::Want &want) const;
    std::shared_ptr<ReminderDataManager> reminderDataManager_ = nullptr;
};

class ReminderEventCustomSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ReminderEventCustomSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
        std::shared_ptr<ReminderDataManager> &reminderDataManager);
    virtual void OnReceiveEvent(const EventFwk::CommonEventData &data);

private:
    std::shared_ptr<ReminderDataManager> reminderDataManager_ = nullptr;
};

class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
public:
    explicit SystemAbilityStatusChangeListener(std::shared_ptr<ReminderDataManager> &reminderDataManager);
    ~SystemAbilityStatusChangeListener() {};
    virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    std::shared_ptr<ReminderDataManager> reminderDataManager_ = nullptr;
};

class ReminderNotificationSubscriber : public NotificationSubscriber {
public:
    explicit ReminderNotificationSubscriber(std::shared_ptr<ReminderDataManager> &reminderDataManager);
    ~ReminderNotificationSubscriber() override;
    void OnConnected() override;
    void OnDisconnected() override;
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override;
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnDied() override;
    void OnDoNotDisturbDateChange(
        const std::shared_ptr<NotificationDoNotDisturbDate> &date) override;
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override;
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;
private:
    std::shared_ptr<ReminderDataManager> reminderDataManager_ = nullptr;
};

    static std::shared_ptr<ReminderNotificationSubscriber> subscriber_;
};
}  // namespace OHOS
}  // namespace Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H
