/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "permission_filter.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "bundle_manager_helper.h"
#include "notification_preferences.h"
#include "notification_analytics_util.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {

void PermissionFilter::OnStart()
{}

void PermissionFilter::OnStop()
{}

AnsStatus PermissionFilter::OnPublish(const std::shared_ptr<NotificationRecord> &record)
{
    bool isForceControl = false;
    bool enable = false;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    ErrCode result =
        NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(record->bundleOption, state);
    if (result == ERR_OK) {
        enable = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
            state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    }
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            enable = bundleManager->CheckApiCompatibility(record->bundleOption);
        }
    }

    if (record->request->IsSystemLiveView()) {
        ANS_LOGE("System live view no need check switch");
        return AnsStatus();
    }

    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = record->request->GetSlotType();
    result = NotificationPreferences::GetInstance()->GetNotificationSlot(record->bundleOption, slotType, slot);
    if (result == ERR_OK) {
        if (slot != nullptr) {
            isForceControl = slot->GetForceControl();
        } else {
            ANS_LOGE("Notification slot not enable.");
            return AnsStatus(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED, "Notification slot not enable.",
                EventSceneId::SCENE_6, EventBranchId::BRANCH_1);
        }
    } else {
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST) {
            ANS_LOGE("Slot type %{public}d not exist.", slotType);
            return AnsStatus(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST, "Slot type not exist.",
                EventSceneId::SCENE_6, EventBranchId::BRANCH_1);
        }
    }

    if (result == ERR_OK) {
        if (!enable && !isForceControl) {
            ANS_LOGE("Enable notifications for bundle is OFF");
            return AnsStatus(ERR_ANS_NOT_ALLOWED, "Notifications is off.",
                EventSceneId::SCENE_6, EventBranchId::BRANCH_1);
        }

        if (record->notification->GetBundleName() != record->notification->GetCreateBundle()) {
            // Publish as bundle
        }
    }
    return AnsStatus();
}
}  // namespace Notification
}  // namespace OHOS