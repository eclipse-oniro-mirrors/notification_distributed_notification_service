/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "reminder_agent_service.h"

#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"
#include "reminder_request_alarm.h"
#include "reminder_bundle_manager_helper.h"
#include "reminder_access_token_helper.h"
#include "reminder_utils.h"
#include "in_process_call_wrapper.h"
#include "ffrt_inner.h"


#include <functional>
#include <iomanip>
#include <sstream>
#include <file_ex.h>

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "notification_request.h"
#include "os_account_manager.h"
#include "hitrace_meter_adapter.h"
#include "reminder_data_manager.h"
#include "notification_helper.h"
#include "reminder_os_account_manager_helper.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

namespace OHOS {
namespace Notification {
constexpr int8_t REMINDER_AGENT_SERVICE_LOAD_STATE = 1;
constexpr int8_t REMINDER_AGENT_SERVICE_UNLOAD_STATE = 0;
constexpr const char* REMINDER_AGENT_SERVICE_CONFIG_PATH = "/data/service/el1/public/notification/reminder_agent_service_config";
constexpr int64_t DELAY_TIME = 60 * 1000 * 1000;
constexpr int32_t REMINDER_AGENT_SERVICE_ID = 3204;
sptr<ReminderAgentService> ReminderAgentService::instance_;
std::mutex ReminderAgentService::instanceMutex_;
std::mutex ReminderAgentService::unloadMutex_;
sptr<ReminderAgentService> ReminderAgentService::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (instance_ == nullptr) {
        instance_ = new (std::nothrow) ReminderAgentService();
        if (instance_ == nullptr) {
            ANS_LOGE("Failed to create AdvancedNotificationService instance");
            return nullptr;
        }
    }

    return instance_;
}

inline bool ReminderAgentService::CheckReminderPermission()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    ErrCode result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        callerToken, "ohos.permission.PUBLISH_AGENT_REMINDER");
    return result == Security::AccessToken::PermissionState::PERMISSION_GRANTED;
}

ErrCode ReminderAgentService::PublishReminder(const ReminderRequest &reminder, int32_t& reminderId)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Publish reminder");
    sptr<ReminderRequest> tarReminder = CreateTarReminderRequest(reminder);
    if (!tarReminder) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundle = GetClientBundleName();
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    bool isAllowUseReminder = false;
    NotificationHelper::AllowUseReminder(bundle, isAllowUseReminder);
    if (!isAllowUseReminder) {
        ANSR_LOGW("The number of reminders exceeds the limit[0].");
        return ERR_REMINDER_NUMBER_OVERLOAD;
    }
    InitReminderRequest(tarReminder, bundle, callingUid);
    NotificationBundleOption bundleOption(tarReminder->GetBundleName(), tarReminder->GetUid());
    bool allowedNotify = false;
    ErrCode result = IN_PROCESS_CALL(NotificationHelper::IsAllowedNotify(bundleOption, allowedNotify));
    if (!tarReminder->IsSystemApp() && (result != ERR_OK || !allowedNotify)) {
        ANSR_LOGW("The application does not request enable notification");
        return ERR_REMINDER_NOTIFICATION_NOT_ENABLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    int32_t ret = rdm->PublishReminder(tarReminder, callingUid);
    if (ret == ERR_OK) {
        reminderId = tarReminder->GetReminderId();
        ChangeReminderAgentLoadConfig(REMINDER_AGENT_SERVICE_LOAD_STATE);
    }
    TryPostDelayUnloadTask(DELAY_TIME);
    return ret;
}

sptr<ReminderRequest> ReminderAgentService::CreateTarReminderRequest(const ReminderRequest &reminder)
{
    sptr<ReminderRequest> tarReminder = nullptr;
    switch (reminder.GetReminderType()) {
        case (ReminderRequest::ReminderType::TIMER): {
            ANSR_LOGI("Publish timer");
            ReminderRequestTimer &timer = (ReminderRequestTimer &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestTimer(timer);
            break;
        }
        case (ReminderRequest::ReminderType::ALARM): {
            ANSR_LOGI("Publish alarm");
            ReminderRequestAlarm &alarm = (ReminderRequestAlarm &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestAlarm(alarm);
            break;
        }
        case (ReminderRequest::ReminderType::CALENDAR): {
            ANSR_LOGI("Publish calendar");
            ReminderRequestCalendar &calendar = (ReminderRequestCalendar &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestCalendar(calendar);
            break;
        }
        default: {
            ANSR_LOGW("PublishReminder fail.");
        }
    }
    return tarReminder;
}

ErrCode ReminderAgentService::InitReminderRequest(sptr<ReminderRequest>& tarReminder,
    const std::string& bundle, const int32_t callingUid)
{
    ANSR_LOGD("is system app: %{public}d", ReminderAccessTokenHelper::IsSystemApp());
    tarReminder->SetSystemApp(ReminderAccessTokenHelper::IsSystemApp());
    tarReminder->InitCreatorBundleName(bundle);
    tarReminder->InitCreatorUid(callingUid);
    if (tarReminder->GetWantAgentInfo() == nullptr || tarReminder->GetMaxScreenWantAgentInfo() == nullptr) {
        ANSR_LOGE("wantagent info is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    std::string wantAgentName = tarReminder->GetWantAgentInfo()->pkgName;
    std::string msWantAgentName = tarReminder->GetMaxScreenWantAgentInfo()->pkgName;
    if (wantAgentName != msWantAgentName && wantAgentName != "" && msWantAgentName != "") {
        ANSR_LOGE("wantAgentName is not same to msWantAgentName, wantAgentName:%{public}s, msWantAgentName:%{public}s",
            wantAgentName.c_str(), msWantAgentName.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    std::string bundleName = bundle;
    if (wantAgentName != bundle && wantAgentName != "") {
        ANSR_LOGI("Set agent reminder, bundle:%{public}s, wantAgentName:%{public}s", bundle.c_str(),
            wantAgentName.c_str());
        bundleName = wantAgentName;
    } else if (msWantAgentName != bundle && msWantAgentName != "") {
        ANSR_LOGI("Set agent reminder, bundle:%{public}s, msWantAgentName:%{public}s", bundle.c_str(),
            msWantAgentName.c_str());
        bundleName = msWantAgentName;
    }
    tarReminder->InitBundleName(bundleName);
    int32_t activeUserId = -1;
    if (ReminderOsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANSR_LOGE("failed to get active user id");
        return ERR_ANS_INVALID_BUNDLE;
    }
    tarReminder->InitUserId(activeUserId);
    tarReminder->InitUid(ReminderBundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(
        tarReminder->GetBundleName(), tarReminder->GetUserId()));
    return ERR_OK;
}

ErrCode ReminderAgentService::CancelReminder(const int32_t reminderId)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Cancel Reminder");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    ErrCode result = rdm->CancelReminder(reminderId, callingUid);
    TryPostDelayUnloadTask(DELAY_TIME);
    return result;
}

ErrCode ReminderAgentService::CancelAllReminders()
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Cancel all reminders");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundleName();
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    ErrCode result = rdm->CancelAllReminders(bundleName, userId, callingUid);
    TryPostDelayUnloadTask(DELAY_TIME);
    return result;
}


ErrCode ReminderAgentService::GetValidReminders(std::vector<ReminderRequestAdaptation> &reminders)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("GetValidReminders");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    reminders.clear();
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    rdm->GetValidReminders(callingUid, reminders);
    ANSR_LOGD("Valid reminders size=%{public}zu", reminders.size());
    TryPostDelayUnloadTask(DELAY_TIME);
    return ERR_OK;
}

ErrCode ReminderAgentService::AddExcludeDate(const int32_t reminderId, const int64_t date)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Add Exclude Date");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    ErrCode result = rdm->AddExcludeDate(reminderId, date, callingUid);
    TryPostDelayUnloadTask(DELAY_TIME);
    return result;
}

ErrCode ReminderAgentService::DelExcludeDates(const int32_t reminderId)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Del Exclude Dates");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    ErrCode result = rdm->DelExcludeDates(reminderId, callingUid);
    TryPostDelayUnloadTask(DELAY_TIME);
    return result;
}

ErrCode ReminderAgentService::GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("Get Exclude Dates");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    ErrCode result = rdm->GetExcludeDates(reminderId, callingUid, dates);
    TryPostDelayUnloadTask(DELAY_TIME);
    return result;
}

void ReminderAgentService::TryPostDelayUnloadTask(int64_t delayTime)
{
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (tryUnloadTask_) {
        ffrt::skip(tryUnloadTask_);
    }
    tryUnloadTask_ = ffrt::submit_h([]() {
        auto rdm = ReminderDataManager::GetInstance();
        if (rdm == nullptr) {
            ANSR_LOGW("Reminder data manager not init!");
            return;
        }
        int32_t reminderCount = rdm->QueryActiveReminderCount();
        if (reminderCount > 0) {
            return;
        }
        ReminderAgentService::GetInstance()->PostDelayUnloadTask();
    }, {}, {}, ffrt::task_attr().delay(delayTime));
}

void ReminderAgentService::PostDelayUnloadTask()
{
    ANSR_LOGI("do unload task");
    ChangeReminderAgentLoadConfig(REMINDER_AGENT_SERVICE_UNLOAD_STATE);
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        ANSR_LOGE("get samgr failed");
        return;
    }
    int32_t ret = samgrProxy->UnloadSystemAbility(REMINDER_AGENT_SERVICE_ID);
    if (ret != ERR_OK) {
        ANSR_LOGE("remove system ability failed");
        return;
    }
}

void ReminderAgentService::ChangeReminderAgentLoadConfig(int8_t reminderAgentState)
{
    if (reminderAgentState_ != reminderAgentState) {
        OHOS::SaveStringToFile(REMINDER_AGENT_SERVICE_CONFIG_PATH, std::to_string(reminderAgentState), true);
        reminderAgentState_ = reminderAgentState;
    }
}

}  // namespace Notification
}  // namespace OHOS
