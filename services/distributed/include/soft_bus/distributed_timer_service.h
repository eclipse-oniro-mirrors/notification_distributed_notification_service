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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TIMER_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TIMER_SERVICE_H

#include "itimer_info.h"
#include <functional>

namespace OHOS {
namespace Notification {

static const int64_t TEN_SECEND = 120000;
static const int64_t THIRTY_SECEND = 600000;

class DistributedTimerInfo : public MiscServices::ITimerInfo {
public:
    DistributedTimerInfo(std::string deviceId): deviceId_(deviceId) {}
    virtual ~DistributedTimerInfo() {};
    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t &type) override;

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool repeat) override;

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t &interval) override;

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override;
private:
    std::string deviceId_;
};

class DistributedTimerService {
public:
    static DistributedTimerService& GetInstance();
    void CancelTimer(const std::string& deviceId);
    void StartTimer(const std::string& deviceId, int64_t deleteTimePoint);
    void StartTimerWithTrigger(
        const std::shared_ptr<MiscServices::ITimerInfo>& timerInfo, uint32_t startAbilityTimeout);
    int64_t GetCurrentTime();

private:
    std::map<std::string, uint64_t> timerIdMap_;
    DistributedTimerService() = default;
    ~DistributedTimerService() = default;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TIMER_SERVICE_H
