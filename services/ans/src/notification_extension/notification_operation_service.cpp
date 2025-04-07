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

#include "notification_operation_service.h"

#include "ans_log_wrapper.h"
#include "notification_analytics_util.h"
#include "time_service_client.h"
#include "ans_inner_errors.h"
#include "distributed_extension_service.h"

namespace OHOS {
namespace Notification {
namespace {
    static const int64_t OPERATION_TIMEOUT = 3000;
}
void OperationTimerInfo::OnTrigger()
{
    DistributedOperationService::GetInstance().HandleOperationTimeOut(timerHashCode_);
}

DistributedOperationService& DistributedOperationService::GetInstance()
{
    static DistributedOperationService distributedOperationService;
    return distributedOperationService;
}

DistributedOperationService::DistributedOperationService()
{
    operationQueue_ = std::make_shared<ffrt::queue>("ans_operation");
    if (operationQueue_ == nullptr) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
    ANS_LOGI("Operation service init successfully.");
}

void DistributedOperationService::AddOperation(const std::string& hashCode,
    const sptr<IAnsOperationCallback> &callback)
{
    int32_t timeout = DistributedExtensionService::GetInstance().GetOperationReplyTimeout();
    int64_t expiredTime = NotificationAnalyticsUtil::GetCurrentTime() + timeout;
    std::shared_ptr<OperationTimerInfo> timerInfo = std::make_shared<OperationTimerInfo>(hashCode);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    uint64_t timerId = timer->CreateTimer(timerInfo);
    timer->StartTimer(timerId, expiredTime);
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iterCallback = callbackMap_.find(hashCode);
    if (iterCallback != callbackMap_.end()) {
        ANS_LOGW("Operation callback has same key %{public}s.", hashCode.c_str());
        callbackMap_.erase(iterCallback);
    }
    callbackMap_.insert_or_assign(hashCode, callback);

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
    ANS_LOGI("Operation add key %{public}s.", hashCode.c_str());
}

void DistributedOperationService::RemoveOperationResponse(const std::string& hashCode)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iterCallback = callbackMap_.find(hashCode);
    if (iterCallback != callbackMap_.end()) {
        callbackMap_.erase(iterCallback);
        ANS_LOGI("Operation callback erase %{public}s", hashCode.c_str());
    }

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        ANS_LOGI("Operation timer erase %{public}s %{public}s", hashCode.c_str(),
            std::to_string(iterTimer->second).c_str());
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
}

void DistributedOperationService::ReplyOperationResponse(const std::string& hashCode, int32_t result)
{
    std::lock_guard<std::mutex> lock(mapLock_);
    auto iterCallback = callbackMap_.find(hashCode);
    if (iterCallback != callbackMap_.end()) {
        iterCallback->second->OnOperationCallback(result);
        callbackMap_.erase(iterCallback);
        ANS_LOGI("Operation callback erase %{public}s", hashCode.c_str());
    }

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        ANS_LOGI("Operation timer erase %{public}s %{public}s", hashCode.c_str(),
            std::to_string(iterTimer->second).c_str());
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
    ANS_LOGI("Operation reply key %{public}s %{public}u.", hashCode.c_str(), result);
}

void DistributedOperationService::HandleOperationTimeOut(const std::string& hashCode)
{
    if (operationQueue_ == nullptr) {
        ANS_LOGE("Operation queue is invalid.");
        return;
    }

    operationQueue_->submit_h([&, hashCode]() {
        ReplyOperationResponse(hashCode, ERR_ANS_OPERATION_TIMEOUT);
    });
}
}
}

