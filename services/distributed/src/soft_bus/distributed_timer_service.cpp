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
#include "notification_config_parse.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {

const int32_t SECOND_TRANSTO_MS = 1000;

void DistributedTimerInfo::OnTrigger()
{
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

int64_t DistributedTimerService::GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

void DistributedTimerService::StartTimerWithTrigger(
    const std::shared_ptr<MiscServices::ITimerInfo>& timerInfo, uint32_t startAbilityTimeout)
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    int64_t timerId = timer->CreateTimer(timerInfo);
    ANS_LOGI("Start ability timeout %{public}u", startAbilityTimeout);
    timer->StartTimer(timerId, GetCurrentTime() + startAbilityTimeout * SECOND_TRANSTO_MS);
}
}
}
