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
#include "advanced_notification_ai_extension_manager.h"

#include "advanced_notification_aggregation_helper.h"
#include "advanced_notification_priority_helper.h"
#include "bool_wrapper.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"
#include "string_wrapper.h"

namespace OHOS {
namespace Notification {
int32_t AdvancedNotificationAiExtensionManager::UpdateNotification(
    const std::vector<sptr<NotificationRequest>> &requests,
    std::vector<sptr<NotificationClassification>> &notificationClassifications)
{
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    ErrCode result = NotificationPreferences::GetInstance()->GetPriorityIntelligentEnabled(enableStatus);
    if (result != ERR_OK) {
        ANS_LOGE("Fail to get enable status: result=%{public}d", result);
        return result;
    }
    uint32_t aiStatus = static_cast<uint32_t>(enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    std::vector<nlohmann::json> commands;
    std::vector<int32_t> results; // Store results for each request
    int32_t needUpdateCount = 0;
    for (auto request : requests) {
        results.push_back(NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
        nlohmann::json command = nlohmann::json::object();
        command[HAS_COMMAND] = false;
        command[AI_STATUS] = aiStatus;
        BuildCommandForUpdate(request, command);
        commands.push_back(command);
        if (command[HAS_COMMAND]) {
            needUpdateCount++;
        }
    }
    if (needUpdateCount == 0) {
        return NotificationAiExtensionWrapper::ErrorCode::ERR_OK;
    }
    // Call AI extension wrapper
    int32_t callResult = NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(
        requests, commands, notificationClassifications, results);
    if (callResult != NotificationAiExtensionWrapper::ErrorCode::ERR_OK) {
        ANS_LOGW("AI extension call failed: result=%{public}d, returning OTHER type", callResult);
    }
    return callResult;
}

void AdvancedNotificationAiExtensionManager::BuildCommandForUpdate(
    const sptr<NotificationRequest> &request, nlohmann::json &command)
{
    if (request == nullptr) {
        ANS_LOGE("BuildCommandForUpdate request is nullptr");
        return;
    }

    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW || IsCollaborationNotification(request)) {
        return;
    }

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    std::string priorityCmd = NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE;
    AdvancedNotificationPriorityHelper::GetInstance()->BuildPriorityCommand(
        priorityCmd, request, command);
    if (command.contains(NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE)) {
        command[HAS_COMMAND] = true;
    }
#endif
#ifdef ANS_FEATURE_AGGREGATION_NOTIFICATION
    std::string aggregationCmd = NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE;
    AdvancedNotificationAggregationHelper::GetInstance()->BuildAggregationCommand(
        aggregationCmd, request, command);
    if (command.contains(NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE)) {
        command[HAS_COMMAND] = true;
    }
#endif
}

bool AdvancedNotificationAiExtensionManager::IsCollaborationNotification(const sptr<NotificationRequest> &request)
{
    auto extendInfo = request->GetExtendInfo();
    AAFwk::IBoolean* ao = nullptr;
    if (extendInfo != nullptr) {
        ao = AAFwk::IBoolean::Query(extendInfo->GetParam(ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG));
    }
    return ao != nullptr && AAFwk::Boolean::Unbox(ao);
}
}  // namespace Notification
}  // namespace OHOS