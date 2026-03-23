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
#include "reminderdatamanagerprivate_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr int32_t WAIT_INIT_TASK = 6;
static constexpr int32_t WAIT_TASK = 1;
static constexpr uint64_t SECONDS = 3600;
static constexpr uint8_t MAX_TIMER_TYPE = 2;
void DoSomethingInterestingWithManager(FuzzedDataProvider* fdp)
{
    Notification::ReminderDataManager::InitInstance();
    auto manager = Notification::ReminderDataManager::GetInstance();
    manager->Init();
    sleep(WAIT_INIT_TASK);

    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    bool value = fdp->ConsumeBool();
    int32_t reminderId = fdp->ConsumeIntegral<int32_t>();
    std::string bundleName = fdp->ConsumeRandomLengthString();
    manager->CancelRemindersImplLocked(bundleName, userId, uid, value);
    manager->CloseRemindersByGroupId(reminderId, bundleName, bundleName);
    sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(SECONDS);
    reminder->InitUserId(userId);
    manager->CheckReminderLimitExceededLocked(uid, reminder);
    manager->CloseReminder(reminder, value);
    uint8_t type = fdp->ConsumeIntegral<uint8_t>() % MAX_TIMER_TYPE;
    auto timerType = static_cast<Notification::ReminderDataManager::TimerType>(type);
    manager->CreateTimerInfo(timerType, reminder);
    manager->FindReminderRequestLocked(reminderId, value);
    manager->GetRecentReminder();
    std::vector<sptr<ReminderRequest>> reminders;
    Notification::ReminderDataManager::ShowLimit limits;
    manager->HandleImmediatelyShow(reminders, limits, value, value);
    manager->HandleExtensionReminder(reminders, static_cast<int8_t>(type));
    manager->HandleRefreshReminder(type, reminder);
    manager->HandleSameNotificationIdShowing(reminder);
    manager->HandleSysTimeChange(reminder);
    manager->IsBelongToSameApp(uid, uid);
    manager->CheckIsSameApp(reminder, uid);
    manager->IsMatched(reminder, userId, uid, value);
    manager->IsMatchedForGroupIdAndPkgName(reminder, bundleName, bundleName);
    manager->IsAllowedNotify(reminder);
    manager->IsReminderAgentReady();
    manager->SetPlayerParam(reminder);
    manager->PlaySoundAndVibrationLocked(reminder);
    manager->PlaySoundAndVibration(reminder);
    manager->StopSoundAndVibrationLocked(reminder);
    manager->StopSoundAndVibration(reminder);
    manager->RemoveFromShowedReminders(reminder);
    std::vector<sptr<ReminderRequest>> immediatelys;
    std::vector<sptr<ReminderRequest>> extensions;
    manager->RefreshRemindersLocked(type, immediatelys, extensions);
    manager->StartTimer(reminder, timerType);
    manager->ResetStates(timerType);
    manager->StopTimer(timerType);
    manager->StopTimerLocked(timerType);
    manager->StartTimerLocked(reminder, timerType);
    manager->ShowActiveReminderExtendLocked(reminder->GetTriggerTimeInMilli(), immediatelys, extensions);
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
