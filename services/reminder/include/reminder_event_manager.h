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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H

#include "common_event_subscriber.h"
#include "notification_subscriber.h"
#include "system_ability_status_change_stub.h"

namespace OHOS::Notification {
class ReminderEventManager {
public:
    static ReminderEventManager& GetInstance();

private:
    ReminderEventManager() = default;
    ~ReminderEventManager() = default;
    ReminderEventManager(ReminderEventManager &other) = delete;
    ReminderEventManager& operator = (const ReminderEventManager &other) = delete;

public:
    void Init();

private:
    void SubscribeEvent();
    void SubscribeSystemAbility(const int32_t systemAbilityId);
    void SubscribeKeyEvent(const int32_t keyCode);

class ReminderEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ReminderEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

class ReminderEventCustomSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ReminderEventCustomSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
public:
    SystemAbilityStatusChangeListener() = default;
    ~SystemAbilityStatusChangeListener() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
};

class ReminderNotificationSubscriber : public NotificationSubscriber {
public:
    ReminderNotificationSubscriber() = default;
    ~ReminderNotificationSubscriber() = default;
    void OnConnected() override {}
    void OnDisconnected() override {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override;
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDied() override {}
    void OnDoNotDisturbDateChange(
        const std::shared_ptr<NotificationDoNotDisturbDate> &date) override {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}
};

private:
    std::shared_ptr<ReminderNotificationSubscriber> subscriber_;
};
}  // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_EVENT_MANAGER_H
