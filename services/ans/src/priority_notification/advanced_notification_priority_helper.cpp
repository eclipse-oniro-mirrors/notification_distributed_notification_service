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
#include "string_wrapper.h"
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
    if (!IsNeedUpdatePriorityType(request) || IsCollaborationNotification(request)) {
        return;
    }
    std::vector<int32_t> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(
        { request }, NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE, results);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_27);
    for (int32_t result : results) {
        ANS_LOGI("UpdateNotification cmd: %{public}s, code: %{public}d, priorityType: %{public}s",
            NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE,
            result, request->GetPriorityNotificationType().c_str());
        if (result == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_OK) {
            continue;
        }
        message.ErrorCode(result);
        std::string cmd = NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE;
        message.Message("cmd: " + cmd);
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
    ANS_LOGI("Priority enableStatus for bundle: %{public}d", static_cast<int32_t>(enableStatus));
    return enableStatus == NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
}

bool AdvancedNotificationPriorityHelper::IsCollaborationNotification(const sptr<NotificationRequest> &request)
{
    auto extendInfo = request->GetExtendInfo();
    AAFwk::IBoolean* ao = nullptr;
    if (extendInfo != nullptr) {
        ao = AAFwk::IBoolean::Query(extendInfo->GetParam(ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG));
    }
    return ao != nullptr && AAFwk::Boolean::Unbox(ao);
}

void AdvancedNotificationPriorityHelper::SetPriorityTypeToExtendInfo(const sptr<NotificationRequest> &request)
{
    std::string priorityType = request->GetPriorityNotificationType();
    if (priorityType == NotificationConstant::PriorityNotificationType::OTHER) {
        return;
    }
    auto extendInfo = request->GetExtendInfo();
    AAFwk::IBoolean* ao = nullptr;
    if (extendInfo == nullptr) {
        extendInfo = std::make_shared<AAFwk::WantParams>();
    }
    extendInfo->SetParam(EXTENDINFO_PRIORITY_TYPE, AAFwk::String::Box(priorityType));
    request->SetExtendInfo(extendInfo);
}

int32_t AdvancedNotificationPriorityHelper::RefreshPriorityType(std::vector<sptr<NotificationRequest>> requests)
{
    if (requests.size() <= 0) {
        return NotificationAiExtensionWrapper::ErrorCode::ERR_OK;
    }
    std::vector<int32_t> results;
    return NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(
        requests, NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE, results);
}
#endif
}  // namespace Notification
}  // namespa OHOS