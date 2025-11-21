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
#include <filesystem>
#include <file_ex.h>

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "access_token_helper.h"
#include "notification_constant.h"
#include "notification_request.h"
#include "reminder_helper.h"
#include "os_account_manager.h"
#include "hitrace_meter_adapter.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "advanced_notification_inline.h"

namespace OHOS {
namespace Notification {
constexpr const char* REMINDER_DB_PATH = "/data/service/el1/public/notification/notification.db";
constexpr const char* REMINDER_AGENT_SERVICE_CONFIG_PATH =
    "/data/service/el1/public/notification/reminder_agent_service_config";
constexpr const char* CALENDAR_DATA_NAME = "com.ohos.calendardata";

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

ErrCode AdvancedNotificationService::SetNotificationRemindType(sptr<Notification> notification, bool isLocal)
{
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    notification->SetRemindType(GetRemindType());
#else
    notification->SetRemindType(NotificationConstant::RemindType::NONE);
#endif
    return ERR_OK;
}

void AdvancedNotificationService::TryStartReminderAgentService()
{
    auto checkCalendarFunc = []() {
        std::vector<int32_t> activeUserIds;
        if (OsAccountManagerHelper::GetInstance().GetForegroundUserIds(activeUserIds) != ERR_OK) {
            ANSR_LOGE("Failed to get active user ids");
            return false;
        }
        std::shared_ptr<BundleManagerHelper> bundleMgr = BundleManagerHelper::GetInstance();
        if (bundleMgr == nullptr) {
            ANSR_LOGE("Failed to get bundle manager");
            return false;
        }
        for (const auto &activeUserId : activeUserIds) {
            int32_t uid = bundleMgr->GetDefaultUidByBundleName(CALENDAR_DATA_NAME, activeUserId);
            if (uid != -1) {
                return true;
            }
        }
        return false;
    };
    if (!checkCalendarFunc()) {
        if (access(REMINDER_DB_PATH, F_OK) != 0) {
            ANS_LOGW("Reminder db no exist");
            return;
        }
        std::string reminderAgentServiceConfig;
        OHOS::LoadStringFromFile(REMINDER_AGENT_SERVICE_CONFIG_PATH, reminderAgentServiceConfig);
        if (reminderAgentServiceConfig != "1") {
            return;
        }
    }
    ANS_LOGI("Reminder db exist, start reminder service");
    ReminderHelper::StartReminderAgentService();
}

ErrCode AdvancedNotificationService::PreReminderInfoCheck()
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_26, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false");
        message.Message("Not systemApp.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NON_SYSTEM_APP));
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        message.Message("Permission denied.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        message.Message("Serial queue is invalid.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_2));
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetReminderInfoByBundles(
    const std::vector<sptr<NotificationBundleOption>> &bundles, std::vector<NotificationReminderInfo> &reminderInfo)
{
    ANS_LOGD("GetReminderInfoByBundles");
    ErrCode result = PreReminderInfoCheck();
    if (result != ERR_OK) {
        return result;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_26, EventBranchId::BRANCH_3);
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        for (const auto &bundle : bundles) {
            uint32_t flags = DEFAULT_SLOT_FLAGS;
            NotificationConstant::SWITCH_STATE enableStatus;
            bool silentReminderEnabled = false;
            NotificationReminderInfo reminder;
            // 1、GenerateValidBundleOption
            sptr<NotificationBundleOption> validBundle = GenerateValidBundleOption(bundle);
            if (validBundle == nullptr) {
                continue;
            }

            // 2、GetNotificationSlotFlagsForBundle
            result = NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(validBundle, flags);
            if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
                result = ERR_OK;
                flags = DEFAULT_SLOT_FLAGS;
            }
            if (result != ERR_OK) {
                ANS_LOGE("%{public}s_%{public}d, get reminderflags failed.",
                    validBundle->GetBundleName().c_str(), validBundle->GetUid());
                message.Message(validBundle->GetBundleName() + "_" + std::to_string(validBundle->GetUid()) +
                    " get reminderflags failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result));
                continue;
            }

            //3、IsSilentReminderEnabled
            result = NotificationPreferences::GetInstance()->IsSilentReminderEnabled(validBundle, enableStatus);
            silentReminderEnabled = ((enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) ||
                (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON));
            if (result != ERR_OK) {
                ANS_LOGE("%{public}s_%{public}d, get silentreminderenable failed.",
                    validBundle->GetBundleName().c_str(), validBundle->GetUid());
                message.Message(validBundle->GetBundleName() + "_" + std::to_string(validBundle->GetUid()) +
                    " get silentreminderenable failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).BranchId(BRANCH_4));
                continue;
            }
            reminder.SetBundleOption(*validBundle);
            reminder.SetReminderFlags(flags);
            reminder.SetSilentReminderEnabled(silentReminderEnabled);
            reminderInfo.emplace_back(reminder);
        }
    }));

    notificationSvrQueue_->wait(handler);
    ANS_LOGI("GetReminderInfoByBundles end");
    NotificationAnalyticsUtil::ReportModifyEvent(
        message.ErrorCode(result).Message("GetReminderInfoByBundles end.").BranchId(BRANCH_5));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetReminderInfoByBundles(
    const std::vector<sptr<NotificationReminderInfo>> &reminderInfo)
{
    ANS_LOGD("SetReminderInfoByBundles");
    ErrCode result = PreReminderInfoCheck();
    if (result != ERR_OK) {
        return result;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_26, EventBranchId::BRANCH_6);
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        for (const auto &reminder : reminderInfo) {
            sptr< NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
                reminder->GetBundleOption());
            uint32_t flags = reminder->GetReminderFlags();
            bool silentReminderEnabled = reminder->GetSilentReminderEnabled();
            // 1、GenerateValidBundleOption
            sptr<NotificationBundleOption> validBundle = GenerateValidBundleOption(bundle);
            if (validBundle == nullptr) {
                continue;
            }

            // 2、SetNotificationSlotFlagsForBundle
            result = NotificationPreferences::GetInstance()->SetNotificationSlotFlagsForBundle(validBundle, flags);
            if (result != ERR_OK) {
                ANS_LOGE("%{public}s_%{public}d, set reminderflags failed.",
                    validBundle->GetBundleName().c_str(), validBundle->GetUid());
                message.Message(validBundle->GetBundleName() + "_" + std::to_string(validBundle->GetUid()) +
                    "_" + std::to_string(flags) + " set reminderflags failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result));
                continue;
            }
            result = UpdateSlotReminderModeBySlotFlags(validBundle, flags);
            if (result != ERR_OK) {
                ANS_LOGE("%{public}s_%{public}d, update slot reminder mode failed.",
                    validBundle->GetBundleName().c_str(), validBundle->GetUid());
                message.Message(validBundle->GetBundleName() + "_" + std::to_string(validBundle->GetUid()) +
                    "_" + std::to_string(flags) + " update slot reminder mode failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).BranchId(BRANCH_7));
                continue;
            }

            //3、SetSilentReminderEnabled
            result = NotificationPreferences::GetInstance()->SetSilentReminderEnabled(
                validBundle, silentReminderEnabled);
            if (result != ERR_OK) {
                ANS_LOGE("%{public}s_%{public}d, set silentreminderenable failed.",
                    validBundle->GetBundleName().c_str(), validBundle->GetUid());
                message.Message(validBundle->GetBundleName() + "_" + std::to_string(validBundle->GetUid()) +
                    "_" + std::to_string(silentReminderEnabled) + " set silentreminderenable failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).BranchId(BRANCH_8));
                continue;
            }
        }
    }));

    notificationSvrQueue_->wait(handler);
    ANS_LOGI("SetReminderInfoByBundles end");
    NotificationAnalyticsUtil::ReportModifyEvent(
        message.ErrorCode(result).Message("SetReminderInfoByBundles end.").BranchId(BRANCH_9));
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
