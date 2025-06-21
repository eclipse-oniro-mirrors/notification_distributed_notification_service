/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef DISTRIBUTED_FEATURE_MASTER
#include "distributed_unlock_listener_oper_service.h"

#include "ans_log_wrapper.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {
namespace {
    static const int64_t OPERATION_TIMEOUT = 30 * 1000;
}
void UnlockListenerTimerInfo::OnTrigger()
{
    UnlockListenerOperService::GetInstance().HandleOperationTimeOut(timerHashCode_);
}

UnlockListenerOperService& UnlockListenerOperService::GetInstance()
{
    static UnlockListenerOperService unlockListenerOperService;
    return unlockListenerOperService;
}

UnlockListenerOperService::UnlockListenerOperService()
{
    operationQueue_ = std::make_shared<ffrt::queue>("ans_operation");
    if (operationQueue_ == nullptr) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
    ANS_LOGI("Operation service init successfully.");
}

void UnlockListenerOperService::AddWantAgent(const std::string& hashCode,
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr)
{
    int32_t timeout = OPERATION_TIMEOUT;
    int64_t expiredTime = GetCurrentTime() + timeout;
    std::shared_ptr<UnlockListenerTimerInfo> timerInfo = std::make_shared<UnlockListenerTimerInfo>(hashCode);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    uint64_t timerId = timer->CreateTimer(timerInfo);
    timer->StartTimer(timerId, expiredTime);
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iterWantAgent = wantAgentMap_.find(hashCode);
    if (iterWantAgent != wantAgentMap_.end()) {
        ANS_LOGW("Operation wantAgent has same key %{public}s.", hashCode.c_str());
        wantAgentMap_.erase(iterWantAgent);
    }
    wantAgentMap_.insert_or_assign(hashCode, wantAgentPtr);

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        ANS_LOGW("Operation timer has same key %{public}s.", hashCode.c_str());
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
    timerMap_.insert_or_assign(hashCode, timerId);
    auto iterOder = std::find(hashCodeOrder_.begin(), hashCodeOrder_.end(), hashCode);
    if (iterOder != hashCodeOrder_.end()) {
        hashCodeOrder_.erase(iterOder);
    }
    hashCodeOrder_.push_back(hashCode);
    ANS_LOGI("Operation add key %{public}s.", hashCode.c_str());
}

void UnlockListenerOperService::RemoveOperationResponse(const std::string& hashCode)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iterWantAgent = wantAgentMap_.find(hashCode);
    if (iterWantAgent != wantAgentMap_.end()) {
        wantAgentMap_.erase(iterWantAgent);
        ANS_LOGI("Operation wantAgent erase %{public}s", hashCode.c_str());
    }

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        ANS_LOGI("Operation timer erase %{public}s %{public}llu", hashCode.c_str(), iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
    auto iterOder = std::find(hashCodeOrder_.begin(), hashCodeOrder_.end(), hashCode);
    if (iterOder != hashCodeOrder_.end()) {
        hashCodeOrder_.erase(iterOder);
    }
}

void UnlockListenerOperService::ReplyOperationResponse()
{
    std::lock_guard<std::mutex> lock(mapLock_);
    ANS_LOGI("UnlockListenerOperService ReplyOperationResponse hashCodeOrder size %{public}u", hashCodeOrder_.size());
    std::vector<std::string> hashcodesToDel;
    for (std::string hashCode : hashCodeOrder_) {
        auto iterWantAgent = wantAgentMap_.find(hashCode);
        if (iterWantAgent != wantAgentMap_.end()) {
            if (LaunchWantAgent(iterWantAgent->second) == ERR_OK) {
                hashcodesToDel.push_back(hashCode);
            }
            wantAgentMap_.erase(iterWantAgent);
        }

        auto iterTimer = timerMap_.find(hashCode);
        if (iterTimer != timerMap_.end()) {
            if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
                return;
            }
            MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
            MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
            timerMap_.erase(iterTimer);
        }
    }
    NotificationHelper::RemoveNotifications(
        hashcodesToDel, NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE);
    hashCodeOrder_.clear();
}

void UnlockListenerOperService::HandleOperationTimeOut(const std::string& hashCode)
{
    if (operationQueue_ == nullptr) {
        ANS_LOGE("Operation queue is invalid.");
        return;
    }

    ANS_LOGI("HandleOperationTimeOut hashCode: %{public}s", hashCode.c_str());
    operationQueue_->submit_h([&, hashCode]() {
        RemoveOperationResponse(hashCode);
    });
}

ErrCode UnlockListenerOperService::LaunchWantAgent(
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    OHOS::AbilityRuntime::WantAgent::TriggerInfo triggerInfo("", nullptr, want, 0);
    sptr<AbilityRuntime::WantAgent::CompletedDispatcher> data;
    ErrCode res =
        AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(wantAgentPtr, nullptr, triggerInfo, data, nullptr);
    ANS_LOGI("LaunchWantAgent result: %{public}d.", static_cast<int32_t>(res));
    return res;
}

int64_t UnlockListenerOperService::GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}
}
}
#endif
