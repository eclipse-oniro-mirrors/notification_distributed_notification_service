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
    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW || IsCollaborationNotification(request)) {
        return;
    }
    std::vector<int32_t> results;
    std::string cmd = NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE;
    RefreshPriorityType(cmd, { request }, results);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_27);
    for (int32_t result : results) {
        ANS_LOGI("UpdateNotification cmd: %{public}s, code: %{public}d, priorityType: %{public}s",
            cmd.c_str(), result, request->GetPriorityNotificationType().c_str());
        if (result == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_OK) {
            continue;
        }
        message.ErrorCode(result);
        message.Message("cmd: " + cmd);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
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

ErrCode AdvancedNotificationPriorityHelper::RefreshPriorityType(const std::string &command,
    const std::vector<sptr<NotificationRequest>> originRequests, std::vector<int32_t> &results)
{
    std::vector<int64_t> strategies;
    std::vector<sptr<NotificationRequest>> requests;
    for (auto &request : originRequests) {
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
        if (bundleOption == nullptr) {
            ANS_LOGW("RefreshPriorityType bundleOption null");
            continue;
        }
        if (request->GetOwnerBundleName().empty()) {
            bundleOption->SetBundleName(request->GetCreatorBundleName());
            bundleOption->SetUid(request->GetCreatorUid());
        } else {
            bundleOption->SetBundleName(request->GetOwnerBundleName());
            bundleOption->SetUid(request->GetOwnerUid());
        }
        NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
        ErrCode dbResult =
            NotificationPreferences::GetInstance()->GetPriorityEnabledByBundleV2(bundleOption, priorityStatus);
        if (dbResult != ERR_OK || priorityStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF ||
            priorityStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF) {
            ANS_LOGI("PriorityEnabledV2 close %{public}s_%{public}d or db fail",
                bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
            continue;
        }
        int64_t strategy = PRIORITY_STRATEGY_DEFAULT;
        dbResult = NotificationPreferences::GetInstance()->GetPriorityStrategyByBundle(bundleOption, strategy);
        if (dbResult != ERR_OK ||
            strategy & static_cast<int64_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY)) {
            ANS_LOGI("StatusAllPriority %{public}s_%{public}d or db fail",
                bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
            continue;
        }
        strategies.emplace_back(strategy);
        requests.emplace_back(request);
    }
    if (requests.size() <= 0) {
        ANS_LOGI("RefreshPriorityType requests empty, originRequests size: %{public}lu", originRequests.size());
        return ERR_OK;
    }
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    ErrCode result = NotificationPreferences::GetInstance()->GetPriorityIntelligentEnabled(enableStatus);
    if (result != ERR_OK) {
        return result;
    }
    uint32_t aiStatus = static_cast<uint32_t>(enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(requests, command, results, aiStatus, strategies);
    return ERR_OK;
}
#endif
}  // namespace Notification
}  // namespa OHOS