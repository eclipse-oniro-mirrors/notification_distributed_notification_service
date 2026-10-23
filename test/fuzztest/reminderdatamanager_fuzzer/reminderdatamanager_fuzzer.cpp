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
#include "reminderdatamanager_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr int32_t WAIT_INIT_TASK = 6;
static constexpr int32_t WAIT_TASK = 1;
static constexpr uint8_t MAX_TIME_CHANGE = 2;
static constexpr uint64_t SECONDS = 3600;
void DoSomethingInterestingWithManager(FuzzedDataProvider* fdp)
{
    Notification::ReminderDataManager::InitInstance();
    auto manager = Notification::ReminderDataManager::GetInstance();
    manager->Init();
    sleep(WAIT_INIT_TASK);

    int32_t reminderId = fdp->ConsumeIntegral<int32_t>();
    int32_t callingUid = fdp->ConsumeIntegral<int32_t>();
    manager->CancelReminder(reminderId, callingUid);
    manager->CancelReminderOnDisplay(reminderId, callingUid);
    manager->CheckExcludeDateParam(reminderId, callingUid);
    int64_t date = fdp->ConsumeIntegral<int64_t>();
    manager->AddExcludeDate(reminderId, date, callingUid);
    manager->DelExcludeDates(reminderId, callingUid);
    std::vector<int64_t> dates;
    manager->GetExcludeDates(reminderId, callingUid, dates);
    manager->RegisterReminderState(callingUid, nullptr);
    manager->UnRegisterReminderState(callingUid);

    EventFwk::Want want;
    want.SetParam(Notification::ReminderRequest::PARAM_REMINDER_ID, reminderId);
    bool value = fdp->ConsumeBool();
    manager->CloseReminder(want, value);
    std::vector<Notification::ReminderRequestAdaptation> reminders;
    manager->GetValidReminders(callingUid, reminders);
    manager->InitUserId();
    std::vector<sptr<Notification::ReminderRequest>> immediatelyReminders;
    std::vector<sptr<Notification::ReminderRequest>> extensionReminders;
    manager->CheckReminderTime(immediatelyReminders, extensionReminders);
    manager->RegisterConfigurationObserver();

    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    manager->OnUserRemove(userId);
    manager->OnBundleMgrServiceStart();
    manager->OnAbilityMgrServiceStart();
    manager->OnUserSwitch(userId);
    sleep(WAIT_TASK);

    sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(SECONDS);
    reminder->InitUserId(userId);
    manager->PublishReminder(reminder, callingUid);
    sleep(WAIT_TASK);
    manager->UpdateReminder(reminder, callingUid);
    sleep(WAIT_TASK);
    uint8_t type = fdp->ConsumeIntegral<uint8_t>() % MAX_TIME_CHANGE;
    manager->RefreshRemindersDueToSysTimeChange(type);
    manager->ShouldAlert(reminder);
    manager->ShowActiveReminder(want);
    manager->SnoozeReminder(want);
    manager->StartRecentReminder();
    std::string bundleName = fdp->ConsumeRandomLengthString();
    manager->CancelAllReminders(bundleName, userId, callingUid);
    manager->CancelAllReminders(userId);
}

void Clear()
{
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
