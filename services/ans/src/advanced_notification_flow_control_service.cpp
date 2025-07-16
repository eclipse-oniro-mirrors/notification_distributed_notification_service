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

#include "advanced_notification_flow_control_service.h"

#include <tuple>
#include <vector>

#include "ans_inner_errors.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {
using TimePoint = std::chrono::system_clock::time_point;
constexpr int32_t TIME_GAP_FOR_SECOND = 1;

void RemoveExpiredTimestamp(std::list<TimePoint> &list, const TimePoint &now)
{
    auto iter = list.begin();
    while (iter != list.end()) {
        if (abs(now - *iter) > std::chrono::seconds(TIME_GAP_FOR_SECOND)) {
            iter = list.erase(iter);
        } else {
            break;
        }
    }
}

ErrCode GlobalFlowController::FlowControl(const std::shared_ptr<NotificationRecord> record, const TimePoint &now)
{
    std::lock_guard<ffrt::mutex> lock(globalFlowControllerMutex_);
    RemoveExpiredTimestamp(globalFlowControllerList_, now);
    if (globalFlowControllerList_.size() >= threshold_) {
        ANS_LOGE("%{public}s", errMsg_.msg.c_str());
        HaMetaMessage message = HaMetaMessage(errMsg_.sceneId, errMsg_.EventBranchId)
            .ErrorCode(errMsg_.errCode).Message(errMsg_.msg);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
        return errMsg_.errCode;
    }
    return ERR_OK;
}

void GlobalFlowController::RecordTimestamp(const TimePoint &now)
{
    std::lock_guard<ffrt::mutex> lock(globalFlowControllerMutex_);
    globalFlowControllerList_.push_back(now);
}

ErrCode CallerFlowController::FlowControl(
    const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, const TimePoint &now)
{
    std::lock_guard<ffrt::mutex> lock(callerFlowControllerMutex_);
    auto callerFlowControlIter = callerFlowControllerMapper_.find(callingUid);
    if (callerFlowControlIter == callerFlowControllerMapper_.end()) {
        return ERR_OK;
    }
    RemoveExpiredTimestamp(*(callerFlowControlIter->second), now);
    if (callerFlowControlIter->second->size() >= threshold_) {
        ANS_LOGE("%{public}s", errMsg_.msg.c_str());
        HaMetaMessage message = HaMetaMessage(errMsg_.sceneId, errMsg_.EventBranchId)
            .ErrorCode(errMsg_.errCode).Message(errMsg_.msg);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
        return errMsg_.errCode;
    }
    return ERR_OK;
}

void CallerFlowController::RecordTimestamp(
    const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, const TimePoint &now)
{
    std::lock_guard<ffrt::mutex> lock(callerFlowControllerMutex_);
    auto callerFlowControlIter = callerFlowControllerMapper_.find(callingUid);
    if (callerFlowControlIter == callerFlowControllerMapper_.end()) {
        callerFlowControllerMapper_[callingUid] = std::make_shared<std::list<TimePoint>>();
        callerFlowControlIter = callerFlowControllerMapper_.find(callingUid);
    }
    callerFlowControlIter->second->push_back(now);
}

void CallerFlowController::RemoveExpired(const TimePoint &now)
{
    std::lock_guard<ffrt::mutex> lock(callerFlowControllerMutex_);
    for (auto iter = callerFlowControllerMapper_.begin(); iter != callerFlowControllerMapper_.end();) {
        auto latest = iter->second->back();
        if (std::chrono::abs(now - latest) > CALLER_FLOW_CONTRL_EXPIRE_TIME) {
            iter = callerFlowControllerMapper_.erase(iter);
        } else {
            ++iter;
        }
    }
}

FlowControlService& FlowControlService::GetInstance()
{
    static FlowControlService flowControlService;
    return flowControlService;
}

FlowControlService::FlowControlService()
{
    DelayedSingleton<NotificationConfigParse>::GetInstance()->GetFlowCtrlConfigFromCCM(threshold_);
    InitGlobalFlowControl();
    InitCallerFlowControl();
}

void FlowControlService::InitGlobalFlowControl()
{
    std::vector<std::tuple<FlowControlSceneType, uint32_t, FlowControlErrMsg>> configs = {
        {
            FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_CREATE,
            threshold_.maxCreateNumPerSecond,
            {
                .msg = "GLOBAL_SYSTEM_NORMAL_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_0,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_UPDATE,
            threshold_.maxUpdateNumPerSecond,
            {
                .msg = "GLOBAL_SYSTEM_NORMAL_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_1,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_CREATE,
            threshold_.maxCreateNumPerSecond,
            {
                .msg = "GLOBAL_SYSTEM_LIVEVIEW_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_2,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_UPDATE,
            threshold_.maxUpdateNumPerSecond,
            {
                .msg = "GLOBAL_SYSTEM_LIVEVIEW_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_3,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_CREATE,
            threshold_.maxCreateNumPerSecond,
            {
                .msg = "GLOBAL_THIRD_PART_NORMAL_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_4,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_UPDATE,
            threshold_.maxUpdateNumPerSecond,
            {
                .msg = "GLOBAL_THIRD_PART_NORMAL_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_5,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_CREATE,
            threshold_.maxCreateNumPerSecond,
            {
                .msg = "GLOBAL_THIRD_PART_LIVEVIEW_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_6,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_UPDATE,
            threshold_.maxUpdateNumPerSecond,
            {
                .msg = "GLOBAL_THIRD_PART_LIVEVIEW_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_7,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
    };

    const int sceneTypeIdx = 0, thresholdIdx = 1, errMsgIdx = 2;
    for (auto iter = configs.cbegin(); iter != configs.cend(); ++iter) {
        globalFlowControllerMapper_[std::get<sceneTypeIdx>(*iter)] =
            std::make_shared<GlobalFlowController>(std::get<thresholdIdx>(*iter), std::get<errMsgIdx>(*iter));
    }
}

void FlowControlService::InitCallerFlowControl()
{
    std::vector<std::tuple<FlowControlSceneType, uint32_t, FlowControlErrMsg>> configs = {
        {
            FlowControlSceneType::CALLER_SYSTEM_NORMAL_CREATE,
            threshold_.maxCreateNumPerSecondPerApp,
            {
                .msg = "CALLER_SYSTEM_NORMAL_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_8,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_SYSTEM_NORMAL_UPDATE,
            threshold_.maxUpdateNumPerSecondPerApp,
            {
                .msg = "CALLER_SYSTEM_NORMAL_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_9,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_CREATE,
            threshold_.maxCreateNumPerSecondPerApp,
            {
                .msg = "CALLER_SYSTEM_LIVEVIEW_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_10,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_UPDATE,
            threshold_.maxUpdateNumPerSecondPerApp,
            {
                .msg = "CALLER_SYSTEM_LIVEVIEW_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_11,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_THIRD_PART_NORMAL_CREATE,
            threshold_.maxCreateNumPerSecondPerApp,
            {
                .msg = "CALLER_THIRD_PART_NORMAL_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_12,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_THIRD_PART_NORMAL_UPDATE,
            threshold_.maxUpdateNumPerSecondPerApp,
            {
                .msg = "CALLER_THIRD_PART_NORMAL_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_13,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_CREATE,
            threshold_.maxCreateNumPerSecondPerApp,
            {
                .msg = "CALLER_THIRD_PART_LIVEVIEW_CREATE flow control", 
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_14,
                .errCode = ERR_ANS_OVER_MAX_ACTIVE_PERSECOND
            }
        },
        {
            FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_UPDATE,
            threshold_.maxUpdateNumPerSecondPerApp,
            {
                .msg = "CALLER_THIRD_PART_LIVEVIEW_UPDATE flow control",
                .sceneId = EventSceneId::SCENE_4,
                .EventBranchId = EventBranchId::BRANCH_15,
                .errCode = ERR_ANS_OVER_MAX_UPDATE_PERSECOND
            }
        },
    };

    const int sceneTypeIdx = 0, thresholdIdx = 1, errMsgIdx = 2;
    for (auto iter = configs.cbegin(); iter != configs.cend(); ++iter) {
        callerFlowControllerMapper_[std::get<sceneTypeIdx>(*iter)] =
            std::make_shared<CallerFlowController>(std::get<thresholdIdx>(*iter), std::get<errMsgIdx>(*iter));
    }
}

ErrCode FlowControlService::FlowControl(
    const std::shared_ptr<NotificationRecord> record, const int32_t callingUid, bool isNotificationExists)
{
    if (record->isNeedFlowCtrl == false) {
        return ERR_OK;
    }
    TimePoint now = std::chrono::system_clock::now();

    auto sceneTypePair = GetSceneTypePair(record, isNotificationExists);
    ErrCode result = ERR_OK;
    auto globalFlowController = globalFlowControllerMapper_[sceneTypePair.first];
    result = globalFlowController->FlowControl(record, now);
    if (result != ERR_OK) {
        return result;
    }

    auto callerFlowController = callerFlowControllerMapper_[sceneTypePair.second];
    result = callerFlowController->FlowControl(record, callingUid, now);
    if (result != ERR_OK) {
        return result;
    }

    globalFlowController->RecordTimestamp(now);
    callerFlowController->RecordTimestamp(record, callingUid, now);

    auto begin = callerFlowControllerMapper_.begin();
    auto end = callerFlowControllerMapper_.end();
    for (auto it = begin; it != end; ++it) {
        it->second->RemoveExpired(now);
    }
    return result;
}

std::pair<FlowControlSceneType, FlowControlSceneType> FlowControlService::GetSceneTypePair(
    const std::shared_ptr<NotificationRecord> record, bool isNotificationExists)
{
    bool isLiveview = record->request->IsCommonLiveView() || record->request->IsSystemLiveView();
    if (record->isThirdparty) {
        // Third-Part caller
        if (isLiveview) {
            if (isNotificationExists) {
                return {FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_UPDATE,
                        FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_UPDATE};
            } else {
                return {FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_CREATE,
                        FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_CREATE};
            }
        } else {
            if (isNotificationExists) {
                return {FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_UPDATE,
                        FlowControlSceneType::CALLER_THIRD_PART_NORMAL_UPDATE};
            } else {
                return {FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_CREATE,
                        FlowControlSceneType::CALLER_THIRD_PART_NORMAL_CREATE};
            }
        }
    }

    // System caller
    if (isLiveview) {
        if (isNotificationExists) {
            return {FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_UPDATE,
                    FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_UPDATE};
        } else {
            return {FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_CREATE,
                    FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_CREATE};
        }
    } else {
        if (isNotificationExists) {
            return {FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_UPDATE,
                    FlowControlSceneType::CALLER_SYSTEM_NORMAL_UPDATE};
        } else {
            return {FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_CREATE,
                    FlowControlSceneType::CALLER_SYSTEM_NORMAL_CREATE};
        }
    }
}
}  // namespace Notification
}  // namespace OHOS