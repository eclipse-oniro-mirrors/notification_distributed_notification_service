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
#include "advanced_notification_aggregation_helper.h"

#include "ans_log_wrapper.h"
#include "notification_constant.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_AGGREGATION_NOTIFICATION
void AdvancedNotificationAggregationHelper::BuildAggregationCommand(std::string& cmdType,
    const sptr<NotificationRequest> &request, nlohmann::json &command, bool hasAggregationSubscriber)
{
    if (!hasAggregationSubscriber) {
        ANS_LOGI("No aggregation subscriber registered, skip aggregation command");
        return;
    }
    int32_t userId = request->GetReceiverUserId();
    if (userId < 0) {
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    }

    // Get aggregation switch states for DEAL
    NotificationConstant::SWITCH_STATE dealSwitchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    ErrCode dealResult = NotificationPreferences::GetInstance()->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, userId, dealSwitchState);
    if (dealResult != ERR_OK) {
        ANS_LOGE("Query deal switch failed");
        return;
    }
    bool dealSwitch = (dealSwitchState == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        dealSwitchState == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    // Get aggregation switch states for LOGISTICS
    NotificationConstant::SWITCH_STATE logisticsSwitchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    ErrCode logisticsResult = NotificationPreferences::GetInstance()->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS, userId, logisticsSwitchState);
    if (logisticsResult != ERR_OK) {
        ANS_LOGE("Query logistics switch failed");
        return;
    }
    bool logisticsSwitch = (logisticsSwitchState == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        logisticsSwitchState == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    if (!dealSwitch && !logisticsSwitch) {
        ANS_LOGI("Both dealSwitch and logisticsSwitch are off");
        return;
    }
    // Build aggregation notification type command
    nlohmann::json aggregationParams = nlohmann::json::object();
    aggregationParams["dealSwitch"] = dealSwitch;
    aggregationParams["logisticsSwitch"] = logisticsSwitch;

    command[cmdType] = aggregationParams;
}
#endif // ANS_FEATURE_AGGREGATION_NOTIFICATION
}  // namespace Notification
}  // namespa OHOS