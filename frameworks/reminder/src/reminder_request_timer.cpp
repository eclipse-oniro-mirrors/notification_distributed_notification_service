/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "reminder_request_timer.h"

#include "ans_log_wrapper.h"

#include <chrono>
#include <cstdlib>

namespace OHOS {
namespace Notification {
ReminderRequestTimer::ReminderRequestTimer(uint64_t countDownTimeInSeconds)
    : ReminderRequest(ReminderRequest::ReminderType::TIMER)
{
    countDownTimeInSeconds_ = countDownTimeInSeconds;
    time_t now;  // unit is seconds.
    (void)time(&now);
    ReminderRequest::SetTriggerTimeInMilli(
        ReminderRequest::GetDurationSinceEpochInMilli(now) + countDownTimeInSeconds_ * ReminderRequest::MILLI_SECONDS);
}

ReminderRequestTimer::ReminderRequestTimer(const ReminderRequestTimer &other) : ReminderRequest(other)
{
    countDownTimeInSeconds_ = other.countDownTimeInSeconds_;
    repeatIntervalInSeconds_ = other.repeatIntervalInSeconds_;
    repeatCount_ = other.repeatCount_;
    remainedRepeatCount_ = other.remainedRepeatCount_;
}

uint64_t ReminderRequestTimer::GetInitInfo() const
{
    return countDownTimeInSeconds_;
}

void ReminderRequestTimer::SetInitInfo(const uint64_t countDownTimeInSeconds)
{
    countDownTimeInSeconds_ = countDownTimeInSeconds;
}

uint64_t ReminderRequestTimer::GetRepeatInterval() const
{
    return repeatIntervalInSeconds_;
}

int32_t ReminderRequestTimer::GetRepeatCount() const
{
    return repeatCount_;
}

int32_t ReminderRequestTimer::GetRemainedRepeatCount() const
{
    return remainedRepeatCount_;
}

void ReminderRequestTimer::SetRepeatInfo(const uint64_t repeatInterval, const int32_t repeatCount,
    const int32_t remainedRepeatCount)
{
    repeatIntervalInSeconds_ = repeatInterval;
    repeatCount_ = repeatCount;
    if (remainedRepeatCount == -1) {
        remainedRepeatCount_ = repeatCount;
    } else {
        remainedRepeatCount_ = remainedRepeatCount;
    }
}

uint64_t ReminderRequestTimer::PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext)
{
    if (repeatIntervalInSeconds_ <= 0) {
        return ReminderRequest::INVALID_LONG_LONG_VALUE;
    }
    if (repeatCount_ != 0 && remainedRepeatCount_ < 0) {
        return ReminderRequest::INVALID_LONG_LONG_VALUE;
    }
    return GetTriggerTimeInMilli();
}

bool ReminderRequestTimer::OnDateTimeChange()
{
    UpdateTimeInfo("onDateTimeChange");
    return false;
}

bool ReminderRequestTimer::OnTimeZoneChange()
{
    UpdateTimeInfo("onTimeZoneChange");
    return false;
}

bool ReminderRequestTimer::UpdateNextReminder()
{
    ANSR_LOGD("called");
    time_t now;
    (void)time(&now);
    uint64_t nowInMilli = ReminderRequest::GetDurationSinceEpochInMilli(now);
    uint64_t tirggerTimeInNilli = GetTriggerTimeInMilli();
    if (tirggerTimeInNilli > nowInMilli) {
        SetExpired(false);
        return true;
    }
    ANSR_LOGI("repeatInterval: %{public}" PRIu64 ", repeatCount: %{public}d, remainedRepeatCount: %{public}d",
        repeatIntervalInSeconds_, repeatCount_, remainedRepeatCount_);
    if (repeatIntervalInSeconds_ > 0) {
        if (repeatCount_ == 0) {
            SetTriggerTimeInMilli(nowInMilli + repeatIntervalInSeconds_ * MILLI_SECONDS);
            SetExpired(false);
            return true;
        }
        if (remainedRepeatCount_ > 0) {
            remainedRepeatCount_--;
            SetTriggerTimeInMilli(nowInMilli + repeatIntervalInSeconds_ * MILLI_SECONDS);
            SetExpired(false);
            return true;
        }
    }
    SetExpired(true);
    return false;
}

void ReminderRequestTimer::UpdateTimeInfo(const std::string &description)
{
    if (IsExpired()) {
        return;
    }

    ANSR_LOGD("%{public}s, update countdown time trigger time", description.c_str());
    time_t now;
    (void)time(&now);  // unit is seconds.
    uint64_t whenToChangeSysTime = ReminderRequest::GetDurationSinceEpochInMilli(now);
    uint64_t lastTriggerTime = GetTriggerTimeInMilli();
    if (lastTriggerTime < whenToChangeSysTime) {
        UpdateNextReminder();
    }
}

bool ReminderRequestTimer::Marshalling(Parcel &parcel) const
{
    return WriteParcel(parcel);
}

bool ReminderRequestTimer::WriteParcel(Parcel &parcel) const
{
    if (ReminderRequest::WriteParcel(parcel)) {
        // write int
        WRITE_UINT64_RETURN_FALSE_LOG(parcel, countDownTimeInSeconds_, "countDownTimeInSeconds");
        WRITE_UINT64_RETURN_FALSE_LOG(parcel, repeatIntervalInSeconds_, "repeatIntervalInSeconds");
        WRITE_INT32_RETURN_FALSE_LOG(parcel, repeatCount_, "repeatCount");
        WRITE_INT32_RETURN_FALSE_LOG(parcel, remainedRepeatCount_, "remainedRepeatCount");
        return true;
    }
    return false;
}

ReminderRequestTimer *ReminderRequestTimer::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) ReminderRequestTimer();
    if (objptr == nullptr) {
        ANSR_LOGE("null objptr");
        return objptr;
    }
    if (!objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool ReminderRequestTimer::ReadFromParcel(Parcel &parcel)
{
    if (ReminderRequest::ReadFromParcel(parcel)) {
        // read int
        READ_UINT64_RETURN_FALSE_LOG(parcel, countDownTimeInSeconds_, "countDownTimeInSeconds");
        READ_UINT64_RETURN_FALSE_LOG(parcel, repeatIntervalInSeconds_, "repeatIntervalInSeconds");
        READ_INT32_RETURN_FALSE_LOG(parcel, repeatCount_, "repeatCount");
        READ_INT32_RETURN_FALSE_LOG(parcel, remainedRepeatCount_, "remainedRepeatCount");
        return true;
    }
    return false;
}
}
}
