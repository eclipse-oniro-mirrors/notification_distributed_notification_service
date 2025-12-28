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

#include "notification_timer_info.h"
#include "ans_log_wrapper.h"
namespace OHOS {
namespace Notification {
void NotificationTimerInfo::SetType(const int &timerInfoType)
{
    type = timerInfoType;
}

void NotificationTimerInfo::SetRepeat(bool timerInfoRepeat)
{
    repeat = timerInfoRepeat;
}

void NotificationTimerInfo::SetInterval(const uint64_t &timerInfoInterval)
{
    interval = timerInfoInterval;
}

void NotificationTimerInfo::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> timerInfoWantAgent)
{
    wantAgent = timerInfoWantAgent;
}

void NotificationTimerInfo::OnTrigger()
{
    ANSR_LOGI("Timing is arrived.");
    Infra::FfrtQueueImpl notificationSvrQueue_ =
        OHOS::Notification::AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (callBack_ != nullptr) {
            callBack_();
            callBack_ = nullptr;
        }
    }));
}

void NotificationTimerInfo::SetCallbackInfo(const std::function<void()> &callBack)
{
    callBack_ = callBack;
}

std::function<void()> NotificationTimerInfo::GetCallBack()
{
    return callBack_;
}
}
}
