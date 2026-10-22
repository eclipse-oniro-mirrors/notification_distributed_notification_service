/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_ADVANCED_NOTIFICATION_PRIORITY_HELPER_H
#define BASE_NOTIFICATION_ANS_SERVICES_ADVANCED_NOTIFICATION_PRIORITY_HELPER_H

#include <queue>

#include "notification_request.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
class NotificationClassification;
#endif
class AdvancedNotificationPriorityHelper : public DelayedSingleton<AdvancedNotificationPriorityHelper> {
public:
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    void UpdatePriorityType(const sptr<NotificationRequest> &request);
    void SetPriorityTypeToExtendInfo(const sptr<NotificationRequest> &request);
    ErrCode RefreshPriorityType(const std::string &cmdType,
        const std::vector<sptr<NotificationRequest>> originRequests, std::vector<int32_t> &results);
    void BuildPriorityCommand(std::string& cmdType, const sptr<NotificationRequest> &request, nlohmann::json &command);
#endif
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
private:
    /**
     * @brief Filter the refresh batch by the bundle level priority strategy.
     *
     * Every request that passes the bundle level priority switch and strategy
     * checks gets its command built (with the intelligent switch state embedded)
     * and its request, result slot and null classification slot appended for the
     * wrapper call; filtered out requests are skipped with a log.
     *
     * @param cmdType Indicates the command type of the refresh.
     * @param aiStatus Indicates the intelligent switch state, 1 on / 0 off.
     * @param originRequests Indicates the whole refresh batch, the filter source.
     * @param requests Indicates the requests that survived the filter.
     * @param commands Indicates the commands built for the surviving requests.
     * @param notificationClassifications Indicates the classification slots of the
     * surviving requests (all null on the refresh chain).
     * @param results Indicates the result slots appended per surviving request.
     */
    void FilterRequestsByStrategy(const std::string &cmdType, uint32_t aiStatus,
        const std::vector<sptr<NotificationRequest>> &originRequests,
        std::vector<sptr<NotificationRequest>> &requests, std::vector<nlohmann::json> &commands,
        std::vector<sptr<NotificationClassification>> &notificationClassifications,
        std::vector<int32_t> &results);
#endif
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_SERVICE_ABILITY_H