/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "advanced_notification_priority_helper.h"

#include "advanced_notification_service.h"
#include "ans_permission_def.h"
#include "bool_wrapper.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
void AdvancedNotificationPriorityHelper::UpdatePriorityType(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("UpdatePriorityType request is nullptr");
        return;
    }
    ANS_LOGI("priorityNotificationType: %{public}s", request->GetPriorityNotificationType().c_str());
    if (!IsNeedUpdatePriorityType(request)) {
        request->SetInnerPriorityNotificationType(NotificationConstant::PriorityNotificationType::OTHER);
        return;
    }
    if (HasUpdatedPriorityType(request)) {
        return;
    }
    std::unordered_map<std::string, sptr<IResult>> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(request, results);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_27);
    for (auto &iter : results) {
        ANS_LOGI("UpdateNotification cmd: %{public}s, \
            returnCode: %{public}d, type: %{public}d, priorityNotificationType: %{public}s", iter.first.c_str(),
            iter.second->returnCode, iter.second->type, request->GetPriorityNotificationType().c_str());
        if (iter.second->returnCode == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_OK) {
            continue;
        }
        message.Message("cmd: " + iter.first);
        message.ErrorCode(iter.second->returnCode);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
}

bool AdvancedNotificationPriorityHelper::IsNeedUpdatePriorityType(const sptr<NotificationRequest> &request)
{
    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        return false;
    }
    bool priorityEnabled = true;
    AdvancedNotificationService::GetInstance()->IsPriorityEnabled(priorityEnabled);
    if (!priorityEnabled) {
        ANS_LOGI("Priority enabled is disabled");
        return false;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("UpdatePriorityType bundleOption null");
        return false;
    }
    if (request->GetOwnerBundleName().empty()) {
        bundleOption->SetBundleName(request->GetCreatorBundleName());
        bundleOption->SetUid(request->GetCreatorUid());
    } else {
        bundleOption->SetBundleName(request->GetOwnerBundleName());
        bundleOption->SetUid(request->GetOwnerUid());
    }
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    if (NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatus) != ERR_OK) {
        ANS_LOGI("GetPriorityEnabledByBundle Preferences fail");
        return false;
    }
    if (enableStatus == NotificationConstant::PriorityEnableStatus::ENABLE) {
        ANS_LOGI("Priority enabled for bundle is enabled");
        return false;
    }
    if (enableStatus == NotificationConstant::PriorityEnableStatus::DISABLE) {
        ANS_LOGI("Priority enabled for bundle is disabled");
        return false;
    }
    return true;
}

bool AdvancedNotificationPriorityHelper::HasUpdatedPriorityType(const sptr<NotificationRequest> &request)
{
    auto extendInfo = request->GetExtendInfo();
    if (extendInfo != nullptr) {
        bool hasUpdated = false;
        AAFwk::IBoolean* ao = AAFwk::IBoolean::Query(extendInfo->GetParam(DELAY_UPDATE_PRIORITY_KEY));
        if (ao != nullptr) {
            hasUpdated = AAFwk::Boolean::Unbox(ao);
        }
        if (hasUpdated) {
            // publish by notification ai for delay updating priority, no need to update again
            ANS_LOGI("delay update priorityNotificationType");
            return true;
        }
        ao = AAFwk::IBoolean::Query(extendInfo->GetParam(ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG));
        if (ao != nullptr) {
            hasUpdated = AAFwk::Boolean::Unbox(ao);
        }
        if (hasUpdated) {
            return true;
        }
    }
    return false;
}
#endif
}  // namespace Notification
}  // namespa OHOS