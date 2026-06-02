/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "reminderdatamanagerannex_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr int32_t WAIT_INIT_TASK = 6;
static constexpr int32_t WAIT_TASK = 1;
static constexpr uint8_t MAX_ACTION_BUTTON_TYPE = 3;
static constexpr uint64_t SECONDS = 3600;
void DoSomethingInterestingWithManager(FuzzedDataProvider* fdp)
{
    Notification::ReminderDataManager::InitInstance();
    auto manager = Notification::ReminderDataManager::GetInstance();
    manager->Init();
    sleep(WAIT_INIT_TASK);

    int32_t reminderId = fdp->ConsumeIntegral<int32_t>();
    EventFwk::Want want;
    want.SetParam(Notification::ReminderRequest::PARAM_REMINDER_ID, reminderId);
    manager->HandleCustomButtonClick(want);
    manager->ClickReminder(want);
    manager->OnLoadReminderEvent();
    sleep(WAIT_TASK);
    manager->OnLoadReminderInFfrt();
    manager->OnDataShareInsertOrDelete();
    std::map<std::string, sptr<Notification::ReminderRequest>> remindersMap;
    manager->OnDataShareUpdate(remindersMap);
    manager->TerminateAlerting(want);
    manager->TerminateAlerting();
    std::vector<sptr<Notification::ReminderRequest>> reminders;
    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    manager->UpdateReminderLanguageLocked(uid, reminders);
    manager->OnLanguageChanged();
    manager->OnRemoveAppMgr();
    manager->IsSystemReady();
    manager->QueryActiveReminderCount();
    manager->StartLoadTimer();
    bool value = fdp->ConsumeBool();
    manager->InitShareReminders(value);
    manager->GetNotifyManager();
    manager->NotifyReminderState(uid);

    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(SECONDS);
    reminder->InitUserId(userId);
    manager->AddToShowedReminders(reminder);
    uint8_t type = fdp->ConsumeIntegral<uint8_t>() % MAX_ACTION_BUTTON_TYPE;
    auto actionButtonType = static_cast<Notification::ReminderRequest::ActionButtonType>(type);
    manager->CheckUpdateConditions(reminder, actionButtonType, reminder->GetActionButtons());
    manager->UpdateAppDatabase(reminder, actionButtonType);
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> equalToVector;
    manager->GenPredicates(predicates, equalToVector);
    DataShare::DataShareValuesBucket valuesBucket;
    manager->GenValuesBucket(valuesBucket, equalToVector);
    manager->InitServiceHandler();
    manager->CancelNotification(reminder);
    manager->CancelAllReminders(userId);
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
