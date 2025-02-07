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

#include "distributed_operation_service.h"

#include "screenlock_common.h"
#include "in_process_call_wrapper.h"

namespace OHOS {
namespace Notification {

UnlockScreenCallback::UnlockScreenCallback(const std::string& eventId) : eventId_(eventId) {}

UnlockScreenCallback::~UnlockScreenCallback() {}

void UnlockScreenCallback::OnCallBack(int32_t screenLockResult)
{
    ANS_LOGI("Unlock Screen result: %{public}d", screenLockResult);
    if (screenLockResult == ScreenLock::ScreenChange::SCREEN_SUCC) {
        OperationService::GetInstance().TriggerOperation(eventId_);
    }
}

OperationService& OperationService::GetInstance()
{
    static OperationService operationService;
    return operationService;
}

void OperationService::AddOperation(OperationInfo operationInfo)
{
    std::lock_guard<std::mutex> lock(operationMutex_);
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
    std::lock_guard<std::mutex> lock(operationMutex_);
    for (auto iter = operationInfoMaps_.begin(); iter != operationInfoMaps_.end();) {
        ANS_LOGI("OperationService erase operation %{public}s %{public}d.",
            iter->second.eventId.c_str(), iter->second.type);
        iter = operationInfoMaps_.erase(iter);
    }
}

void OperationService::TriggerOperation(std::string eventId)
{
    std::lock_guard<std::mutex> lock(operationMutex_);
    auto iter = operationInfoMaps_.find(eventId);
    if (iter == operationInfoMaps_.end()) {
        ANS_LOGW("Operation not exist %{public}s.", eventId.c_str());
        return;
    }
    if (iter->second.type == OperationType::OPERATION_CLICK_JUMP) {
        auto ret = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->StartAbility(iter->second.want));
        operationInfoMaps_.erase(iter);
        ANS_LOGI("StartAbility result:%{public}s %{public}d", eventId.c_str(), ret);
        return;
    }
}

void OperationService::TimeOutOperation(std::string eventId)
{
    std::lock_guard<std::mutex> lock(operationMutex_);
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
