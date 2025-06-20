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

#ifndef BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
#define BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
#ifdef DISTRIBUTED_FEATURE_MASTER

#include <functional>

#include "ffrt.h"
#include "itimer_info.h"

namespace OHOS {
namespace Notification {
struct UnlockListenerWant {
    uint64_t timer;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = nullptr;
};

class UnlockListenerTimerInfo : public MiscServices::ITimerInfo {
public:
    UnlockListenerTimerInfo(std::string timerHashCode) : timerHashCode_(timerHashCode) {};
    virtual ~UnlockListenerTimerInfo() {};
    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t &type) override {};

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool repeat) override {};

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t &interval) override {};

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override {};

private:
    std::string timerHashCode_;
};

class UnlockListenerOperService {
public:
    static UnlockListenerOperService& GetInstance();
    void AddWantAgent(const std::string& hashCode,
        const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr);
    void ReplyOperationResponse();
    void HandleOperationTimeOut(const std::string& hashCode);
    void RemoveOperationResponse(const std::string& hashCode);
    ErrCode LaunchWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr);

private:
    UnlockListenerOperService();
    ~UnlockListenerOperService() = default;

    int64_t GetCurrentTime();

private:
    std::mutex mapLock_;
    std::shared_ptr<ffrt::queue> operationQueue_ = nullptr;
    std::vector<std::string> hashCodeOrder_;
    std::map<std::string, uint64_t> timerMap_;
    std::map<std::string, std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> wantAgentMap_;
};
} // namespace OHOS
} // namespace Notification
#endif  // DISTRIBUTED_FEATURE_MASTER
#endif  // BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
