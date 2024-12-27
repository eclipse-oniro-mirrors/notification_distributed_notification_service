/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

namespace OHOS {
    bool DoSomethingInterestingWithManager(const char* data, size_t size)
    {
        std::string bundleName(data);
        int32_t userId = static_cast<int32_t>(GetU32Data(data));
        int32_t uid = static_cast<int32_t>(GetU32Data(data));
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        uint64_t date = static_cast<uint64_t>(GetU32Data(data));
        bool value = static_cast<bool>(GetU32Data(data));
        uint8_t type = static_cast<uint8_t>(GetU32Data(data));
        EventFwk::Want want;
        constexpr uint64_t seconds = 1200;
        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(seconds);

        Notification::ReminderDataManager::InitInstance(nullptr);
        auto manager = Notification::ReminderDataManager::GetInstance();
        manager->Init(false);
        manager->Dump();
        manager->CancelAllReminders(bundleName, userId, uid);
        sptr<Notification::NotificationBundleOption> option = new Notification::NotificationBundleOption(
            bundleName, uid);
        manager->CancelReminder(reminderId, option);
        manager->CheckExcludeDateParam(reminderId, option);
        manager->AddExcludeDate(reminderId, date, option);
        manager->DelExcludeDates(reminderId, option);

        std::vector<uint64_t> dates;
        manager->GetExcludeDates(reminderId, option, dates);
        manager->CloseReminder(want, value);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        manager->GetValidReminders(option, reminders);
        manager->Init(value);
        manager->InitUserId();
        std::vector<sptr<Notification::ReminderRequest>> immediatelyReminders;
        std::vector<sptr<Notification::ReminderRequest>> extensionReminders;
        manager->CheckReminderTime(immediatelyReminders, extensionReminders);

        manager->RegisterConfigurationObserver();
        manager->OnUserRemove(userId);
        manager->OnBundleMgrServiceStart();
        manager->OnAbilityMgrServiceStart();
        manager->OnUserSwitch(userId);
        manager->OnProcessDiedLocked(option);
        manager->RefreshRemindersDueToSysTimeChange(type);
        manager->ShouldAlert(reminder);
        manager->ShowActiveReminder(want);
        manager->SnoozeReminder(want);

        manager->HandleCustomButtonClick(want);
        manager->ClickReminder(want);
        manager->TerminateAlerting(want);
        return true;
    }

    bool DoSomethingInterestingWithReminder(const char* data, size_t size)
    {
        std::string bundleName(data);
        int32_t userId = static_cast<int32_t>(GetU32Data(data));
        int32_t uid = static_cast<int32_t>(GetU32Data(data));
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        bool value = static_cast<bool>(GetU32Data(data));
        constexpr uint64_t seconds = 1200;
        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequestTimer(seconds);
        auto manager = Notification::ReminderDataManager::GetInstance();

        sptr<Notification::NotificationBundleOption> option = new Notification::NotificationBundleOption(
            bundleName, uid);
        manager->OnLanguageChanged();
        manager->OnRemoveAppMgr();
        manager->CancelAllReminders(userId);
        manager->CheckUpdateConditions(reminder, Notification::ReminderRequest::ActionButtonType::INVALID,
            reminder->GetActionButtons());
        manager->GetCustomRingUri(reminder);
        manager->CancelRemindersImplLocked(bundleName, userId, uid);
        manager->CloseRemindersByGroupId(reminderId, bundleName, bundleName);
        manager->CancelNotification(reminder);
        manager->CheckReminderLimitExceededLocked(option, reminder);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        manager->GetImmediatelyShowRemindersLocked(reminders);
        manager->GetSoundUri(reminder);
        manager->AddToShowedReminders(reminder);

        manager->IsAllowedNotify(reminder);
        manager->PlaySoundAndVibrationLocked(reminder);
        manager->PlaySoundAndVibration(reminder);
        manager->StopSoundAndVibrationLocked(reminder);
        manager->StopSoundAndVibration(reminder);
        manager->RemoveFromShowedReminders(reminder);
        manager->RemoveReminderLocked(reminderId);
        manager->SetActiveReminder(reminder);
        manager->SetAlertingReminder(reminder);
        manager->ShowActiveReminderExtendLocked(reminder, reminders);

        std::vector<sptr<Notification::ReminderRequest>> extensionReminders;
        std::vector<sptr<Notification::ReminderRequest>> immediatelyReminders;
        manager->PublishReminder(reminder, option);
        manager->FindReminderRequestLocked(reminderId);
        manager->FindReminderRequestLocked(reminderId, bundleName);
        manager->GetRecentReminderLocked();
        manager->HandleImmediatelyShow(immediatelyReminders, value);
        manager->HandleExtensionReminder(extensionReminders, 0);
        manager->HandleSameNotificationIdShowing(reminder);
        manager->IsBelongToSameApp(option, option);
        manager->CheckIsSameApp(reminder, option);
        manager->ShowReminder(reminder, value, value, value, value);
        return true;
    }

    bool Clear()
    {
        auto manager = Notification::ReminderDataManager::GetInstance();
        if (manager->queue_ != nullptr) {
            auto handler = manager->queue_->submit_h(std::bind([]() {}));
            manager->queue_->wait(handler);
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithManager(ch, size);
        OHOS::DoSomethingInterestingWithReminder(ch, size);
        OHOS::Clear();
        free(ch);
        ch = nullptr;
    }
    return 0;
}
