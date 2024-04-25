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

#include "advanced_notification_service.h"

#include <functional>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "access_token_helper.h"
#include "notification_constant.h"
#include "notification_request.h"
#include "os_account_manager.h"
#include "hitrace_meter_adapter.h"
#include "reminder_data_manager.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
inline bool AdvancedNotificationService::CheckReminderPermission()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    ErrCode result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        callerToken, "ohos.permission.PUBLISH_AGENT_REMINDER");
    return result == Security::AccessToken::PermissionState::PERMISSION_GRANTED;
}

ErrCode AdvancedNotificationService::PublishReminder(sptr<ReminderRequest> &reminder)
{
    ANSR_LOGI("Publish reminder");
    if (!reminder) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }
    ANSR_LOGD("is system app: %{public}d", AccessTokenHelper::IsSystemApp());
    reminder->SetSystemApp(AccessTokenHelper::IsSystemApp());
    sptr<NotificationRequest> notificationRequest = reminder->GetNotificationRequest();
    std::string bundle = GetClientBundleName();
    reminder->InitCreatorBundleName(bundle);
    if (reminder->GetWantAgentInfo() == nullptr || reminder->GetMaxScreenWantAgentInfo() == nullptr) {
        ANSR_LOGE("wantagent info is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    std::string wantAgentName = reminder->GetWantAgentInfo()->pkgName;
    std::string msWantAgentName = reminder->GetMaxScreenWantAgentInfo()->pkgName;
    if (wantAgentName != msWantAgentName && wantAgentName != "" && msWantAgentName != "") {
        ANSR_LOGE("wantAgentName is not same to msWantAgentName, wantAgentName:%{public}s, msWantAgentName:%{public}s",
            wantAgentName.c_str(), msWantAgentName.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    if (wantAgentName != bundle && wantAgentName != "") {
        ANSR_LOGI("Set agent reminder, bundle:%{public}s, wantAgentName:%{public}s", bundle.c_str(),
            wantAgentName.c_str());
        SetAgentNotification(notificationRequest, wantAgentName);
    } else if (msWantAgentName != bundle && msWantAgentName != "") {
        ANSR_LOGI("Set agent reminder, bundle:%{public}s, msWantAgentName:%{public}s", bundle.c_str(),
            msWantAgentName.c_str());
        SetAgentNotification(notificationRequest, msWantAgentName);
    }
    sptr<NotificationBundleOption> bundleOption = nullptr;
    ErrCode result = PrepareNotificationInfo(notificationRequest, bundleOption);
    if (result != ERR_OK) {
        ANSR_LOGW("PrepareNotificationInfo fail");
        return result;
    }
    bool allowedNotify = false;
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (!reminder->IsSystemApp() && (result != ERR_OK || !allowedNotify)) {
        ANSR_LOGW("The application does not request enable notification");
        return ERR_REMINDER_NOTIFICATION_NOT_ENABLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->PublishReminder(reminder, bundleOption);
}

ErrCode AdvancedNotificationService::CancelReminder(const int32_t reminderId)
{
    ANSR_LOGI("Cancel Reminder");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->CancelReminder(reminderId, bundleOption);
}

ErrCode AdvancedNotificationService::CancelAllReminders()
{
    ANSR_LOGI("Cancel all reminders");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->CancelAllReminders(bundleOption->GetBundleName(), userId);
}


ErrCode AdvancedNotificationService::GetValidReminders(std::vector<sptr<ReminderRequest>> &reminders)
{
    ANSR_LOGI("GetValidReminders");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    reminders.clear();
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    rdm->GetValidReminders(bundleOption, reminders);
    ANSR_LOGD("Valid reminders size=%{public}zu", reminders.size());
    return ERR_OK;
}

ErrCode AdvancedNotificationService::AddExcludeDate(const int32_t reminderId, const uint64_t date)
{
    ANSR_LOGI("Add Exclude Date");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANSR_LOGW("Generate bundle option failed!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    return rdm->AddExcludeDate(reminderId, date, bundleOption);
}

ErrCode AdvancedNotificationService::DelExcludeDates(const int32_t reminderId)
{
    ANSR_LOGI("Del Exclude Dates");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANSR_LOGW("Generate bundle option failed!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    return rdm->DelExcludeDates(reminderId, bundleOption);
}

ErrCode AdvancedNotificationService::GetExcludeDates(const int32_t reminderId, std::vector<uint64_t>& dates)
{
    ANSR_LOGI("Get Exclude Dates");
    if (!CheckReminderPermission()) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANSR_LOGW("Generate bundle option failed!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        ANSR_LOGW("Reminder data manager not init!");
        return ERR_NO_INIT;
    }
    return rdm->GetExcludeDates(reminderId, bundleOption, dates);
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
NotificationConstant::RemindType AdvancedNotificationService::GetRemindType()
{
    bool remind = localScreenOn_;
    if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::DEFAULT) {
        bool remoteUsing = false;
        ErrCode result = DistributedScreenStatusManager::GetInstance()->CheckRemoteDevicesIsUsing(remoteUsing);
        if (result != ERR_OK) {
            remind = true;
        }
        if (!localScreenOn_ && !remoteUsing) {
            remind = true;
        }
    } else if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::ALWAYS_REMIND) {
        remind = true;
    } else if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::DO_NOT_REMIND) {
        remind = false;
    }

    if (localScreenOn_) {
        if (remind) {
            return NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
        } else {
            return NotificationConstant::RemindType::DEVICE_ACTIVE_DONOT_REMIND;
        }
    } else {
        if (remind) {
            return NotificationConstant::RemindType::DEVICE_IDLE_REMIND;
        } else {
            return NotificationConstant::RemindType::DEVICE_IDLE_DONOT_REMIND;
        }
    }
}
#endif

ErrCode AdvancedNotificationService::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() { remindType = GetRemindType(); }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::SetNotificationRemindType(sptr<Notification> notification, bool isLocal)
{
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    notification->SetRemindType(GetRemindType());
#else
    notification->SetRemindType(NotificationConstant::RemindType::NONE);
#endif
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
