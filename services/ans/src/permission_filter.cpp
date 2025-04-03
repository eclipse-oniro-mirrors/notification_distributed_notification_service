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

namespace OHOS {
namespace Notification {
void PermissionFilter::OnStart()
{}

void PermissionFilter::OnStop()
{}

ErrCode PermissionFilter::OnPublish(const std::shared_ptr<NotificationRecord> &record)
{
    bool isForceControl = false;
    bool enable = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_1);
    ErrCode result =
        NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(record->bundleOption, enable);
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            enable = bundleManager->CheckApiCompatibility(record->bundleOption);
        }
    }

    if (record->request->IsSystemLiveView()) {
        ANS_LOGI("System live view no need check switch.");
        return ERR_OK;
    }

    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = record->request->GetSlotType();
    message.SlotType(slotType);
    result = NotificationPreferences::GetInstance()->GetNotificationSlot(record->bundleOption, slotType, slot);
    if (result == ERR_OK) {
        if (slot != nullptr) {
            isForceControl = slot->GetForceControl();
        } else {
            message.ErrorCode(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED).Message("Slot type not exist.");
            NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED;
            ANS_LOGE("Type[%{public}d] slot does not exist", slotType);
        }
    }

    if (result == ERR_OK) {
        if (!enable && !isForceControl) {
            message.ErrorCode(ERR_ANS_NOT_ALLOWED).Message("Notifications is off.");
            NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            ANS_LOGE("Enable notifications for bundle is OFF");
            return ERR_ANS_NOT_ALLOWED;
        }

        if (record->notification->GetBundleName() != record->notification->GetCreateBundle()) {
            // Publish as bundle
        }
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
