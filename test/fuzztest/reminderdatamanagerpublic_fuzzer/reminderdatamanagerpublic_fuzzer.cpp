/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "reminder_data_manager.h"
#include "reminder_request_timer.h"
#include "reminderdatamanagerpublic_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr int32_t WAIT_INIT_TASK = 6;
static constexpr int32_t WAIT_TASK = 1;
static constexpr uint64_t SECONDS = 3600;
static constexpr uint8_t MAX_TIMER_TYPE = 2;
static constexpr uint8_t MAX_ACTION_BUTTON_TYPE = 3;
void DoSomethingInterestingWithManager(FuzzedDataProvider* fdp)
{
    Notification::ReminderDataManager::InitInstance();
    auto manager = Notification::ReminderDataManager::GetInstance();
    manager->Init();
    sleep(WAIT_INIT_TASK);

    manager->LoadReminderFromDb();
    sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(SECONDS);
    bool value = fdp->ConsumeBool();
    manager->ShowReminder(reminder, value, value, value, value);
    Notification::NotificationRequest notificationRequest;
    manager->SlienceNotification(value, value, notificationRequest);
    manager->SnoozeReminderImpl(reminder);
    uint8_t type = fdp->ConsumeIntegral<uint8_t>() % MAX_ACTION_BUTTON_TYPE;
    manager->StopAlertingReminder(reminder);
    manager->SetActiveReminder(reminder);
    manager->StartExtensionAbility(reminder, static_cast<int8_t>(type));
    manager->SetAlertingReminder(reminder);
    std::string reason = fdp->ConsumeRandomLengthString();
    manager->TerminateAlerting(reminder, reason);
    manager->UpdateAndSaveReminderLocked(reminder);
    manager->UpdateAndSaveReminderLocked(reminder, value);
    manager->ConnectAppMgr();
    auto actionButtonType = static_cast<Notification::ReminderRequest::ActionButtonType>(type);
    manager->CheckNeedNotifyStatus(reminder, actionButtonType);
    manager->GetFullPath(reason);
    uint32_t uid = fdp->ConsumeIntegral<int32_t>();
    manager->IsActionButtonDataShareValid(reminder, uid);
    int32_t id = fdp->ConsumeIntegral<int32_t>();
    manager->RemoveReminderLocked(id, value);
    manager->GetResourceMgr(reason, id);
    manager->CloseCustomRingFileDesc(id, reason);
    manager->ReportSysEvent(reminder);
    int64_t time = fdp->ConsumeIntegral<int64_t>();
    manager->ReportTimerEvent(time, value);
    manager->ReportUserDataSizeEvent();
    manager->LoadShareReminders();
    auto channel = static_cast<Notification::ReminderRequest::RingChannel>(type);
    manager->ConvertRingChannel(channel);
    manager->CheckSoundConfig(reminder);
    std::map<std::string, sptr<Notification::ReminderRequest>> reminders;
    manager->UpdateShareReminders(reminders);
    std::vector<sptr<Notification::ReminderRequest>> remindersFromDb;
    manager->UpdateReminderFromDb(remindersFromDb);
    manager->CancelReminderToDb(id, id);
    manager->CheckAndCloseShareReminder(reminder);
    manager->CollapseNotificationPanel();
    Notification::ReminderDataManager::ShowLimit limits;
    manager->CheckShowLimit(limits, reminder);
}

void Clear()
{
    auto manager = Notification::ReminderDataManager::GetInstance();
    if (manager->queue_ != nullptr) {
        auto handler = manager->queue_->submit_h(std::bind([]() {}));
        manager->queue_->wait(handler);
    }
    Notification::ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithManager(&fdp);
    OHOS::Clear();
    return 0;
}
