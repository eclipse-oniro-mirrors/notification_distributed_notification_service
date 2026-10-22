/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "single_timer_scheduler.h"

#include <cinttypes>
#include <memory>

#include "ans_log_wrapper.h"
#include "itimer_info.h"

namespace OHOS {
namespace Notification {
namespace {
class SchedulerTimerInfo : public MiscServices::ITimerInfo {
public:
    SchedulerTimerInfo() = default;
    ~SchedulerTimerInfo() override = default;

    void OnTrigger() override
    {
        std::function<void()> callback = nullptr;
        {
            std::lock_guard<ffrt::mutex> lock(callbackMutex_);
            callback = callback_;
        }
        if (callback != nullptr) {
            callback();
        }
    }

    void SetType(const int32_t &timerInfoType) override
    {
        type = timerInfoType;
    }

    void SetRepeat(bool timerInfoRepeat) override
    {
        repeat = timerInfoRepeat;
    }

    void SetInterval(const uint64_t &timerInfoInterval) override
    {
        interval = timerInfoInterval;
    }

    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>) override {}

    void SetCallbackInfo(const std::function<void()> &callback)
    {
        std::lock_guard<ffrt::mutex> lock(callbackMutex_);
        callback_ = callback;
    }

private:
    std::function<void()> callback_ = nullptr;
    ffrt::mutex callbackMutex_;
};
} // namespace

SingleTimerScheduler::~SingleTimerScheduler()
{
    Disarm();
}

void SingleTimerScheduler::Init(const std::string &timerName, const NextTriggerTimeProvider &provider,
    const ExpiryCallbackFactory &callbackFactory)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    timerName_ = timerName;
    provider_ = provider;
    callbackFactory_ = callbackFactory;
    initialized_ = true;
}

void SingleTimerScheduler::ReArm()
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (!initialized_ || !provider_) {
        return;
    }
    int64_t triggerTime = provider_();
    if (triggerTime == armedTime_) {
        return;
    }
    if (triggerTime == 0) {
        DisarmLocked();
        ANS_LOGD("Timer disarmed, no deadline left, timer: %{public}s", timerName_.c_str());
        return;
    }
    if (!ArmOnce(triggerTime)) {
        ANS_LOGW("Timer arm failed, keep unarmed for retry, timer: %{public}s, trigger time: "
            "%{public}" PRId64, timerName_.c_str(), triggerTime);
        armedTime_ = 0;
        return;
    }
    armedTime_ = triggerTime;
    ANS_LOGD("Timer armed, timer: %{public}s, trigger time: %{public}" PRId64,
        timerName_.c_str(), triggerTime);
}

void SingleTimerScheduler::Disarm()
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    DisarmLocked();
}

bool SingleTimerScheduler::ArmOnce(int64_t triggerTime)
{
    timerImpl_.StopTimer();
    timerImpl_.DestroyTimer();

    if (!callbackFactory_) {
        ANS_LOGE("Timer expiry callback factory unavailable, skip timer arm");
        return false;
    }
    std::function<void()> expiryCallback = callbackFactory_();
    if (expiryCallback == nullptr) {
        ANS_LOGE("Timer expiry callback unavailable, skip timer arm, timer: %{public}s",
            timerName_.c_str());
        return false;
    }
    auto timerInfo = std::make_shared<SchedulerTimerInfo>();
    timerInfo->SetCallbackInfo(expiryCallback);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);

    uint8_t timerTypeWakeup = static_cast<uint8_t>(timerInfo->TIMER_TYPE_WAKEUP);
    uint8_t timerTypeExact = static_cast<uint8_t>(timerInfo->TIMER_TYPE_EXACT);
    int32_t timerType = static_cast<int32_t>(timerTypeWakeup | timerTypeExact);
    timerInfo->SetType(timerType);
    timerInfo->SetName(timerName_);
    timerImpl_.CreateTimer(timerInfo);

    return timerImpl_.StartTimer(triggerTime);
}

void SingleTimerScheduler::DisarmLocked()
{
    timerImpl_.StopTimer();
    timerImpl_.DestroyTimer();
    armedTime_ = 0;
}
} // namespace Notification
} // namespace OHOS
