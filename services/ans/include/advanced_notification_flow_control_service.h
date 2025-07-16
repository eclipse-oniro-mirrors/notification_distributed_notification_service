/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H

#include <ctime>
#include <list>
#include <memory>
#include <mutex>

#include "errors.h"
#include "singleton.h"
#include "ans_const_define.h"
#include "notification_record.h"
#include "notification_analytics_util.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
struct FlowControlThreshold {
    uint32_t maxCreateNumPerSecond = MAX_CREATE_NUM_PERSECOND;
    uint32_t maxUpdateNumPerSecond = MAX_UPDATE_NUM_PERSECOND;
    uint32_t maxCreateNumPerSecondPerApp = MAX_CREATE_NUM_PERSECOND_PERAPP;
    uint32_t maxUpdateNumPerSecondPerApp = MAX_UPDATE_NUM_PERSECOND_PERAPP;
};

struct FlowControlErrMsg {
    std::string msg;
    EventSceneId sceneId;
    EventBranchId EventBranchId;
    ErrCode errCode;
};

enum FlowControlSceneType {
    GLOBAL_SYSTEM_NORMAL_CREATE,
    GLOBAL_SYSTEM_NORMAL_UPDATE,
    GLOBAL_SYSTEM_LIVEVIEW_CREATE,
    GLOBAL_SYSTEM_LIVEVIEW_UPDATE,
    GLOBAL_THIRD_PART_NORMAL_CREATE,
    GLOBAL_THIRD_PART_NORMAL_UPDATE,
    GLOBAL_THIRD_PART_LIVEVIEW_CREATE,
    GLOBAL_THIRD_PART_LIVEVIEW_UPDATE,
    CALLER_SYSTEM_NORMAL_CREATE,
    CALLER_SYSTEM_NORMAL_UPDATE,
    CALLER_SYSTEM_LIVEVIEW_CREATE,
    CALLER_SYSTEM_LIVEVIEW_UPDATE,
    CALLER_THIRD_PART_NORMAL_CREATE,
    CALLER_THIRD_PART_NORMAL_UPDATE,
    CALLER_THIRD_PART_LIVEVIEW_CREATE,
    CALLER_THIRD_PART_LIVEVIEW_UPDATE,
};

class GlobalFlowController {
public:
    using TimePoint = std::chrono::system_clock::time_point;
    GlobalFlowController(const uint32_t threshold, const FlowControlErrMsg& errMsg)
        : threshold_(threshold), errMsg_(errMsg) {}

    /**
     * @brief Flow control for all apps.
     *
     * @param record Notification record. User should ensure that record is not nullptr.
     * @param now Current time.
     * @return Returns ERR_OK when the call frequency doesn't reach the threshold.
     */
    ErrCode FlowControl(const std::shared_ptr<NotificationRecord> record, const TimePoint &now);

    /**
     * @brief Add a timestamp to flow control list.
     *
     * @param now Current time.
     */
    void RecordTimestamp(const TimePoint &now);

private:
    uint32_t threshold_;
    FlowControlErrMsg errMsg_;
    ffrt::mutex globalFlowControllerMutex_;
    std::list<TimePoint> globalFlowControllerList_;
};

class CallerFlowController {
public:
    using TimePoint = std::chrono::system_clock::time_point;
    CallerFlowController(const uint32_t threshold, const FlowControlErrMsg& errMsg)
        : threshold_(threshold), errMsg_(errMsg) {}

    /**
     * @brief Flow control for specified app which owns the notification.
     *
     * @param record Notification record. User should ensure that record is not nullptr.
     * @param callingUid Uid of caller.
     * @param now Current time.
     * @return Returns ERR_OK when the call frequency doesn't reach the threshold.
     */
    ErrCode FlowControl(
        const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, const TimePoint &now);

    /**
     * @brief Add a timestamp to flow control list.
     *
     * @param record Notification record to acquire owner uid of notification. User should ensure that record is not nullptr.
     * @param callingUid Uid of caller.
     * @param now Current time.
     */
    void RecordTimestamp(
        const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, const TimePoint &now);

    /**
     * @brief Remove expired appliacation record.
     *
     * @param now Current time.
     */
    void RemoveExpired(const TimePoint &now);
private:
    uint32_t threshold_;
    FlowControlErrMsg errMsg_;
    ffrt::mutex callerFlowControllerMutex_;
    std::map<int32_t, std::shared_ptr<std::list<TimePoint>>> callerFlowControllerMapper_;
};

class FlowControlService {
public:
    DISALLOW_COPY_AND_MOVE(FlowControlService);
    static FlowControlService& GetInstance();

    /**
     * @brief Flow control total entrance.
     *
     * @param record Notification record. User should ensure that record is not nullptr.
     * @param callingUid Uid of caller.
     * @param isNotificationExists true when update notification and false when create notification.
     */
    ErrCode FlowControl(
        const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, bool isNotificationExists);

private:
    FlowControlService();
    void InitGlobalFlowControl();
    void InitCallerFlowControl();
    std::pair<FlowControlSceneType, FlowControlSceneType> GetSceneTypePair(
        const std::shared_ptr<NotificationRecord> record, bool isNotificationExists);

private:
    FlowControlThreshold threshold_;
    std::map<FlowControlSceneType, std::shared_ptr<GlobalFlowController>> globalFlowControllerMapper_;
    std::map<FlowControlSceneType, std::shared_ptr<CallerFlowController>> callerFlowControllerMapper_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H