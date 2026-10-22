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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SINGLE_TIMER_SCHEDULER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SINGLE_TIMER_SCHEDULER_H

#include <cstdint>
#include <functional>
#include <string>

#include "ffrt.h"
#include "timer_impl.h"

namespace OHOS {
namespace Notification {
/**
 * @brief Single absolute-time one-shot timer scheduler with an unchanged-target
 *        no-op guard.
 *
 * Lock order contract: the provider is invoked with the scheduler mutex held and
 * may take its own data lock (scheduler mutex first, one way) but must not call
 * back into ReArm/Disarm. A failed arm keeps the armed moment 0, so the next
 * ReArm retries the whole arming instead of being silenced by the no-op guard.
 */
class SingleTimerScheduler {
public:
    using NextTriggerTimeProvider = std::function<int64_t()>;
    using ExpiryCallbackFactory = std::function<std::function<void()>()>;

    SingleTimerScheduler() = default;
    virtual ~SingleTimerScheduler();

    /**
     * @brief Initializes the scheduler; must be called before the first ReArm.
     *
     * @param timerName Indicates the timer name passed to the time service.
     * @param provider Indicates the next trigger time provider (absolute epoch
     *        milliseconds, 0 means nothing to schedule).
     * @param callbackFactory Indicates the expiry callback factory, invoked at arm
     *        time; a null return skips the arming.
     */
    void Init(const std::string &timerName, const NextTriggerTimeProvider &provider,
        const ExpiryCallbackFactory &callbackFactory);

    /**
     * @brief Re-arms the timer with the provider's next trigger time (unified entry
     *        for every schedule mutation): unchanged target is a no-op, zero disarms.
     */
    void ReArm();

    /**
     * @brief Stops and destroys the timer and resets the armed moment bookkeeping.
     */
    void Disarm();

protected:
    /**
     * @brief Arms one fresh one-shot timer (virtual test seam, called with the
     *        scheduler mutex held).
     *
     * @param triggerTime Indicates the absolute epoch millisecond trigger time.
     * @return Returns true when the timer was started successfully.
     */
    virtual bool ArmOnce(int64_t triggerTime);

private:
    void DisarmLocked();

    ffrt::mutex mutex_;
    Infra::TimerImpl timerImpl_;
    int64_t armedTime_ {0};
    bool initialized_ {false};
    std::string timerName_;
    NextTriggerTimeProvider provider_;
    ExpiryCallbackFactory callbackFactory_;
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SINGLE_TIMER_SCHEDULER_H
