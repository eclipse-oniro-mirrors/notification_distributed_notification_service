/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "reminder_request_calendar.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "notification_slot.h"
#include "os_account_manager.h"
#include "reminder_event_manager.h"
#include "time_service_client.h"
#include "singleton.h"
#include "locale_config.h"
#include "datashare_predicates_object.h"
#include "datashare_value_object.h"
#include "datashare_helper.h"
#include "data_share_permission.h"
#include "datashare_errno.h"
#include "datashare_template.h"
#include "system_ability_definition.h"
#include "app_mgr_constants.h"
#include "iservice_registry.h"
#include "config_policy_utils.h"
#include "hitrace_meter_adapter.h"
#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t ALL_SA_READY_FLAG = 2;  // bundle service and ability service ready.
// The maximum number of applications that can be displayed at a time
constexpr int32_t ONE_HAP_MAX_NUMBER_SHOW_AT_ONCE = 10;
// The maximum number of system that can be displayed at a time
constexpr int32_t TOTAL_MAX_NUMBER_SHOW_AT_ONCE = 500;
// The maximun number of system that can be start extension count
constexpr int32_t TOTAL_MAX_NUMBER_START_EXTENSION = 100;
constexpr int32_t CONNECT_EXTENSION_INTERVAL = 100;
}

bool ReminderDataManager::IsSystemReady()
{
    return saReadyFlag_ >= ALL_SA_READY_FLAG;
}

bool ReminderDataManager::IsActionButtonDataShareValid(const sptr<ReminderRequest>& reminder,
    const uint32_t callerTokenId)
{
    auto actionButtonMap = reminder->GetActionButtons();
    for (auto it = actionButtonMap.begin(); it != actionButtonMap.end(); ++it) {
        ReminderRequest::ActionButtonInfo& buttonInfo = it->second;
        if (buttonInfo.dataShareUpdate->uri.empty()) {
            continue;
        }
        Uri uri(buttonInfo.dataShareUpdate->uri);
        auto ret = DataShare::DataSharePermission::VerifyPermission(callerTokenId, uri, false);
        if (ret != DataShare::E_OK) {
            ANSR_LOGE("publish failed, DataSharePermission::VerifyPermission return error[%{public}d],",
                static_cast<int32_t>(ret));
            return false;
        }
    }
    return true;
}

void ReminderDataManager::HandleAutoDeleteReminder(const int32_t notificationId, const int32_t uid,
    const int64_t autoDeletedTime)
{
    ANSR_LOGI("auto delete reminder start");
    std::vector<sptr<ReminderRequest>> showedReminder;
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        showedReminder = showedReminderVector_;
    }
    for (auto reminder : showedReminder) {
        if (reminder == nullptr) {
            continue;
        }

        if (reminder->GetUid() != uid || notificationId != reminder->GetNotificationId() ||
            reminder->GetAutoDeletedTime() != autoDeletedTime) {
            continue;
        }
        CloseReminder(reminder, true);
        UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CLOSE);
        CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::CLOSE);
    }
    StartRecentReminder();
}

void ReminderDataManager::OnBundleMgrServiceStart()
{
    saReadyFlag_.fetch_add(1);
}

void ReminderDataManager::OnAbilityMgrServiceStart()
{
    saReadyFlag_.fetch_add(1);
}

bool ReminderDataManager::GetCustomRingFileDesc(const sptr<ReminderRequest>& reminder,
    Global::Resource::ResourceManager::RawFileDescriptor& desc)
{
    // obtains the resource manager
    std::lock_guard<std::mutex> locker(resourceMutex_);
    soundResource_ = GetResourceMgr(reminder->GetBundleName(), reminder->GetUid());
    if (soundResource_ == nullptr) {
        ANSR_LOGE("GetResourceMgr fail.");
        return false;
    }
    auto result = soundResource_->GetRawFileDescriptor(reminder->GetCustomRingUri(), desc);
    if (result != Global::Resource::SUCCESS) {
        ANSR_LOGE("GetRawFileDescriptor fail[%{public}d].", static_cast<int32_t>(result));
        return false;
    }
    return true;
}

void ReminderDataManager::CloseCustomRingFileDesc(const int32_t reminderId, const std::string& customRingUri)
{
    std::lock_guard<std::mutex> locker(resourceMutex_);
    if (soundResource_ == nullptr) {
        ANSR_LOGE("ResourceManager is nullptr.");
        return;
    }
    auto result = soundResource_->CloseRawFileDescriptor(customRingUri);
    if (result != Global::Resource::SUCCESS) {
        ANSR_LOGE("CloseRawFileDescriptor fail[%{public}d]", static_cast<int32_t>(result));
    }
    ANSR_LOGI("Stop custom sound, reminderId:[%{public}d].", reminderId);
    soundResource_ = nullptr;
}

void ReminderDataManager::ReportSysEvent(const sptr<ReminderRequest>& reminder)
{
#ifdef HAS_HISYSEVENT_PART
    std::string event = "ALARM_TRIGGER";
    std::string bundleName = reminder->GetBundleName();
    int32_t uid = reminder->GetUid();
    int32_t type = static_cast<int32_t>(reminder->GetReminderType());
    int32_t repeat = static_cast<int32_t>(reminder->IsRepeat());
    uint64_t triggerTime = reminder->GetTriggerTimeInMilli();
    int32_t ringTime = static_cast<int32_t>(reminder->GetRingDuration());
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::NOTIFICATION, event, HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "UID", uid, "NAME", bundleName, "TYPE", type, "REPEAT", repeat, "TRIGGER_TIME", triggerTime,
        "RING_TIME", ringTime);
#endif
}

bool ReminderDataManager::CheckShowLimit(std::unordered_map<std::string, int32_t>& limits, int32_t& totalCount,
    sptr<ReminderRequest>& reminder)
{
    if (totalCount > TOTAL_MAX_NUMBER_SHOW_AT_ONCE) {
        ANSR_LOGE("The maximum number of displays that can be displayed at a time has been reached.");
        return false;
    }
    ++totalCount;
    std::string key = std::to_string(reminder->GetUid()) + "_" + std::to_string(reminder->GetTriggerTimeInMilli());
    auto iter = limits.find(key);
    if (iter == limits.end()) {
        limits[key] = 1;
        return true;
    }
    if (iter->second > ONE_HAP_MAX_NUMBER_SHOW_AT_ONCE) {
        ANSR_LOGE("The maximum number of displays that can be displayed in a single app[%{public}s] has been reached",
            reminder->GetBundleName().c_str());
        return false;
    }
    ++iter->second;
    return true;
}

void ReminderDataManager::OnDataShareInsertOrDelete()
{
    LoadShareReminders();
    std::vector<sptr<ReminderRequest>> immediatelyReminders;
    std::vector<sptr<ReminderRequest>> extensionReminders;
    CheckReminderTime(immediatelyReminders, extensionReminders);
    HandleImmediatelyShow(immediatelyReminders, false);
    StartRecentReminder();
}

void ReminderDataManager::OnDataShareUpdate(const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    UpdateShareReminders(reminders);
}

void ReminderDataManager::UpdateShareReminders(const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if (!(*it)->IsShare() || (*it)->GetReminderType() != ReminderRequest::ReminderType::CALENDAR) {
            continue;
        }
        int32_t reminderId = (*it)->GetReminderId();
        std::string identifier = (*it)->GetIdentifier();
        auto iter = reminders.find(identifier);
        if (iter == reminders.end()) {
            continue;
        }
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>((*it).GetRefPtr());
        calendar->Copy(iter->second);
        if ((*it)->IsShowing()) {
            ShowReminder((*it), false, false, false, false);
        }
    }
}

void ReminderDataManager::AsyncStartExtensionAbility(const sptr<ReminderRequest> &reminder, int32_t times,
    const int8_t type, int32_t& count)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        ANSR_LOGE("ReminderDataManager is nullptr.");
        return;
    }
    if (!manager->IsSystemReady()) {
        ANSR_LOGE("bundle service or ability service not ready.");
        return;
    }
    if (!reminder->IsSystemApp()) {
        ANSR_LOGE("Start extension ability failed, is not system app");
        return;
    }
    if (count > TOTAL_MAX_NUMBER_START_EXTENSION) {
        ANSR_LOGE("The maximum number of start extension has been reached.");
        return;
    }
    ++count;
    times--;
    bool ret = ReminderDataManager::StartExtensionAbility(reminder, type);
    if (!ret && times > 0 && serviceQueue_ != nullptr) {
        ANSR_LOGD("StartExtensionAbilty failed, reminder times: %{public}d", times);
        ffrt::task_attr taskAttr;
        taskAttr.delay(CONNECT_EXTENSION_INTERVAL);
        auto callback = [reminder, times, type]() {
            int32_t count = 0;
            ReminderDataManager::AsyncStartExtensionAbility(reminder, times, type, count);
        };
        serviceQueue_->submit(callback, taskAttr);
    }
}

ErrCode ReminderDataManager::UpdateReminder(const sptr<ReminderRequest>& reminder, const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    sptr<ReminderRequest> reminderOld = FindReminderRequestLocked(reminder->GetReminderId(), false);
    bool existInMemory = true;
    if (nullptr != reminderOld) {
        if (reminderOld->IsShowing()) {
            ANSR_LOGW("Reminder already showing, update reminder failed.");
            return ERR_REMINDER_NOT_EXIST;
        }
    } else {
        existInMemory = false;
        std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
        if (!store_->IsReminderExist(reminder->GetReminderId(), reminder->GetCreatorUid())) {
            ANSR_LOGW("Reminder not find, update reminder failed.");
            return ERR_REMINDER_NOT_EXIST;
        }
    }
    uint32_t callerTokenId = IPCSkeleton::GetCallingTokenID();
    if (callerTokenId == 0) {
        ANSR_LOGE("pushlish failed, callerTokenId is 0");
        return ERR_REMINDER_CALLER_TOKEN_INVALID;
    }
    if (!IsActionButtonDataShareValid(reminder, callerTokenId)) {
        return ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED;
    }

    UpdateAndSaveReminderLocked(reminder, existInMemory);
    queue_->submit([this, reminder]() {
        StartRecentReminder();
    });
    return ERR_OK;
}

void ReminderDataManager::UpdateAndSaveReminderLocked(const sptr<ReminderRequest>& reminder, const bool isInMemory)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    if (reminder->GetTriggerTimeInMilli() == ReminderRequest::INVALID_LONG_LONG_VALUE) {
        ANSR_LOGW("now publish reminder is expired. reminder is =%{public}s", reminder->Dump().c_str());
        reminder->SetExpired(true);
    }
    if (isInMemory) {
        for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
            if (reminder->GetReminderId() == (*it)->GetReminderId() && !(*it)->IsShare()) {
                *it = reminder;
                break;
            }
        }
    } else {
        reminderVector_.push_back(reminder);
    }
    store_->UpdateOrInsert(reminder);
}
}
}
