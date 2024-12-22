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
#include "distributed_timer_service.h"
#include "distributed_service.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {

void DistributedTimerInfo::OnTrigger()
{
    DistributedService::GetInstance().ReportDeviceStatus(deviceId_);
}

void DistributedTimerInfo::SetType(const int32_t &typeInfo)
{
    type = typeInfo;
}

void DistributedTimerInfo::SetRepeat(bool repeatInfo)
{
    repeat = repeatInfo;
}

void DistributedTimerInfo::SetInterval(const uint64_t &intervalInfo)
{
    interval = intervalInfo;
}

void DistributedTimerInfo::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgentInfo)
{
    wantAgent = wantAgentInfo;
}

DistributedTimerService& DistributedTimerService::GetInstance()
{
    static DistributedTimerService distributedTimerService;
    return distributedTimerService;
}

void DistributedTimerService::CancelTimer(const std::string& deviceId)
{
    ANS_LOGD("Enter");
    if (timerIdMap_.find(deviceId) == timerIdMap_.end()) {
        return;
    }
    int64_t timerId = timerIdMap_[deviceId];
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(timerIdMap_[deviceId]);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(timerIdMap_[deviceId]);
    timerIdMap_.erase(deviceId);
    ANS_LOGI("Dans timer delete %{public}s %{public}lld.", deviceId.c_str(), timerId);
}

void DistributedTimerService::StartTimer(const std::string& deviceId, int64_t deleteTimePoint)
{
    CancelTimer(deviceId);
    std::shared_ptr<DistributedTimerInfo> timerInfo = std::make_shared<DistributedTimerInfo>(deviceId);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    int64_t timerId = timer->CreateTimer(timerInfo);
    timer->StartTimer(timerId, deleteTimePoint);
    timerIdMap_[deviceId] = timerId;
    ANS_LOGI("Dans start auto delete %{public}s %{public}lld %{public}lld.", deviceId.c_str(),
        deleteTimePoint, timerId);
}

}
}
