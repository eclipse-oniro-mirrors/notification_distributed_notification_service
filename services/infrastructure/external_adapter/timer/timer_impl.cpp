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

#include "timer_impl.h"
#include "errors.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace Infra {

TimerImpl::TimerImpl()
{
    timer_ = MiscServices::TimeServiceClient::GetInstance();
}

TimerImpl::~TimerImpl()
{
    timer_ = nullptr;
    timerId_ = 0;
}

void TimerImpl::CreateTimer(std::shared_ptr<MiscServices::ITimerInfo> timerOptions)
{
    if (timer_ == nullptr) {
        ANS_LOGE("timer is null");
        return;
    }
    if (timerId_ == 0) {
        timerId_ = timer_->CreateTimer(timerOptions);
    }
}

void TimerImpl::StartTimer(int64_t triggerTime)
{
    if (timer_ == nullptr) {
        ANS_LOGE("timer is null");
        return;
    }
    timer_->StartTimer(timerId_, triggerTime);
}

void TimerImpl::StopTimer()
{
    if (timer_ == nullptr) {
        ANS_LOGE("timer is null");
        return;
    }
    if (timerId_ > 0) {
        timer_->StopTimer(timerId_);
    }
}

void TimerImpl::DestroyTimer()
{
    if (timer_ == nullptr) {
        ANS_LOGE("timer is null");
        return;
    }
    if (timerId_ > 0) {
        timer_->DestroyTimer(timerId_);
        timerId_ = 0;
    }
}

} // Infra
} // Notification
} // OHOS
