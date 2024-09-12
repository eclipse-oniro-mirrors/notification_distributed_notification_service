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
#include "access_token_helper.h"
#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "reminder_request_calendar.h"
#include "in_process_call_wrapper.h"
#ifdef DEVICE_STANDBY_ENABLE
#include "standby_service_client.h"
#include "allow_type.h"
#endif
#include "ipc_skeleton.h"
#include "notification_slot.h"
#include "os_account_manager.h"
#include "reminder_event_manager.h"
#include "time_service_client.h"
#include "singleton.h"
#include "locale_config.h"
#include "bundle_manager_helper.h"
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
}
}
