/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_SERVICE_CHECK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_SERVICE_CHECK_H

#include "itimer_info.h"
#include "datashare_helper.h"
#include "common_event_subscriber.h"
#include "data_ability_observer_stub.h"

namespace OHOS::Notification {
class ReminderServiceCheck {
public:
    ReminderServiceCheck() = default;
    ~ReminderServiceCheck() = default;

    static ReminderSerivceCheck& GetInstance();

    bool CheckNeedStartService();

    void StartListen();
    void StopListen();

public:
    void OnTimeChange();
    void OnTimer();
    void OnDataChange();

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    bool RegisterObserver();
    bool UnRegisterObserver();
    bool Query();

    void StartTimer();
    void StopTimer();
    void SubscribeEvent();
    void UnSubscribeEvent();
    bool QueryDataUid();

private:
    std::mutex mutex_;  // for observer_ and timerId_
    std::shared_ptr<DataShare::DataShareObserver> observer_;
    std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber_;

    int32_t userId_{100};
    uint64_t timerId_{0};

private:
class ReminderDataObserver : public DataShare::DataShareObserver {
public:
    ReminderDataObserver() = default;
    ~ReminderDataObserver() = default;

    /**
     * @brief Notification of data changes.
     */
    void OnChange(const ChangeInfo& info) override;
};

private:
class ReminderTimerInfo : public MiscServices::ITimerInfo {
    ReminderTimerInfo() = default;
    ~ReminderTimerInfo() = default;

    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t& type) override;

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool repeat) override;

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t& interval) override;

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent) override;
};

private:
class ReminderEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ReminderEventSubscriber(const EventFwk::CommonEventSubscribeInfo& subscriberInfo);
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};
};
}

#endif