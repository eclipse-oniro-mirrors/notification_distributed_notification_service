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

#ifndef ANS_TIMER_IMPL_H
#define ANS_TIMER_IMPL_H

#include "time_service_client.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class TimerImpl {
public:
    TimerImpl();

    ~TimerImpl();

    void CreateTimer(std::shared_ptr<MiscServices::ITimerInfo> timerOptions);

    void StartTimer(int64_t triggerTime);

    void StopTimer();

    void DestroyTimer();

private:
    sptr<MiscServices::TimeServiceClient> timer_ {nullptr};
    uint64_t timerId_ {0};
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif  // ANS_TIMER_IMPL_H
