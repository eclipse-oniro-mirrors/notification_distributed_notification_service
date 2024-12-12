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

#include "advanced_notification_inline.cpp"

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

ErrCode AdvancedNotificationService::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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

void AdvancedNotificationService::TryStartReminderAgentService()
{
    auto checkCalendarFunc = []() {
        int32_t activeUserId = 0;
        if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
            ANSR_LOGE("Failed to get active user id");
            return false;
        }
        std::shared_ptr<BundleManagerHelper> bundleMgr = BundleManagerHelper::GetInstance();
        if (bundleMgr == nullptr) {
            ANSR_LOGE("Failed to get bundle manager");
            return false;
        }
        int32_t uid = bundleMgr->GetDefaultUidByBundleName(CALENDAR_DATA_NAME, activeUserId);
        return uid != -1;
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
}  // namespace Notification
}  // namespace OHOS
