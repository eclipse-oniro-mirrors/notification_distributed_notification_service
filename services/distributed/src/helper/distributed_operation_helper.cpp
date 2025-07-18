/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "distributed_operation_helper.h"

#ifdef SCREENLOCK_MGR_ENABLE
#include "screenlock_common.h"
#endif
#include "in_process_call_wrapper.h"
#include "distributed_service.h"
#include "analytics_util.h"

namespace OHOS {
namespace Notification {

#ifdef SCREENLOCK_MGR_ENABLE
UnlockScreenCallback::UnlockScreenCallback(const std::string& eventId) : eventId_(eventId) {}

UnlockScreenCallback::~UnlockScreenCallback() {}

void UnlockScreenCallback::OnCallBack(int32_t screenLockResult)
{
    ANS_LOGI("Unlock Screen result: %{public}d", screenLockResult);
    if (screenLockResult == ScreenLock::ScreenChange::SCREEN_SUCC) {
        OperationService::GetInstance().TriggerOperation(eventId_);
    } else {
        AnalyticsUtil::GetInstance().SendEventReport(0, -1, "unlock screen failed");
        AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, -1, BRANCH7_ID,
            "unlock screen failed");
    }
}
#endif

OperationService& OperationService::GetInstance()
{
    static OperationService operationService;
    return operationService;
}

void OperationService::AddOperation(OperationInfo operationInfo)
{
    std::lock_guard<ffrt::mutex> lock(operationMutex_);
    auto iter = operationInfoMaps_.find(operationInfo.eventId);
    if (iter != operationInfoMaps_.end()) {
        ANS_LOGW("OperationService operation exist %{public}s.", operationInfo.eventId.c_str());
        return;
    }
    ANS_LOGI("OperationService add operation %{public}s %{public}d.",
        operationInfo.eventId.c_str(), operationInfo.type);
    operationInfoMaps_[operationInfo.eventId] = operationInfo;
}

void OperationService::HandleScreenEvent()
{
    std::lock_guard<ffrt::mutex> lock(operationMutex_);
    for (auto iter = operationInfoMaps_.begin(); iter != operationInfoMaps_.end();) {
        ANS_LOGI("OperationService erase operation %{public}s %{public}d.",
            iter->second.eventId.c_str(), iter->second.type);
        iter = operationInfoMaps_.erase(iter);
    }
}

void OperationService::TriggerOperation(std::string eventId)
{
    std::lock_guard<ffrt::mutex> lock(operationMutex_);
    auto iter = operationInfoMaps_.find(eventId);
    if (iter == operationInfoMaps_.end()) {
        ANS_LOGW("Operation not exist %{public}s.", eventId.c_str());
        return;
    }
    if (iter->second.type == OperationType::DISTRIBUTE_OPERATION_JUMP) {
        auto ret = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->StartAbility(iter->second.want));
        std::string errorReason = "pull up success";
        if (ret == ERR_OK) {
            AnalyticsUtil::GetInstance().OperationalReporting(iter->second.deviceTypeId,
                HaOperationType::COLLABORATE_JUMP, NotificationConstant::SlotType::LIVE_VIEW);
            AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE,
                NotificationConstant::SlotType::LIVE_VIEW, BRANCH3_ID, errorReason, ANS_CUSTOMIZE_CODE);
        } else {
            AnalyticsUtil::GetInstance().SendEventReport(0, ret, "pull up failed");
        }
        AnalyticsUtil::GetInstance().SendHaReport(MODIFY_ERROR_EVENT_CODE, ret, BRANCH8_ID, errorReason);
        operationInfoMaps_.erase(iter);
        ANS_LOGI("StartAbility result:%{public}s %{public}d", eventId.c_str(), ret);
        return;
    }
}

void OperationService::TimeOutOperation(std::string eventId)
{
    std::lock_guard<ffrt::mutex> lock(operationMutex_);
    auto iter = operationInfoMaps_.find(eventId);
    if (iter == operationInfoMaps_.end()) {
        ANS_LOGI("Operation not exist %{public}s.", eventId.c_str());
        return;
    }
    ANS_LOGI("OperationService timeout operation %{public}s %{public}d.",
        iter->second.eventId.c_str(), iter->second.type);
    operationInfoMaps_.erase(iter);
}
}
}
