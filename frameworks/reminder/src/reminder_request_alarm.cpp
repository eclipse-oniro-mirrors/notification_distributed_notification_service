/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "reminder_request_alarm.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
const uint8_t ReminderRequestAlarm::MINUTES_PER_HOUR = 60;
const int8_t ReminderRequestAlarm::DEFAULT_SNOOZE_TIMES = 3;

ReminderRequestAlarm::ReminderRequestAlarm(uint8_t hour, uint8_t minute, const std::vector<uint8_t> daysOfWeek)
    : ReminderRequest(ReminderRequest::ReminderType::ALARM)
{
    SetSnoozeTimes(DEFAULT_SNOOZE_TIMES);
    hour_ = hour;
    minute_ = minute;
    CheckParamValid();
    SetRepeatDaysOfWeek(true, daysOfWeek);
    SetTriggerTimeInMilli(GetNextTriggerTime(true));
}

ReminderRequestAlarm::ReminderRequestAlarm(const ReminderRequestAlarm &other) : ReminderRequest(other)
{
    hour_ = other.hour_;
    minute_ = other.minute_;
    repeatDaysOfWeek_ = other.repeatDaysOfWeek_;
    ANSR_LOGD("hour_=%{public}d, minute_=%{public}d, repeatDaysOfWeek_=%{public}d",
        hour_, minute_, other.repeatDaysOfWeek_);
}

void ReminderRequestAlarm::CheckParamValid() const
{
    if (hour_ >= HOURS_PER_DAY) {
        ANSR_LOGE("setted hour is not between [0, 24)");
        return;
    }
    if (minute_ >= MINUTES_PER_HOUR) {
        ANSR_LOGE("setted minute is not between [0, 60)");
        return;
    }
}

bool ReminderRequestAlarm::IsRepeatReminder() const
{
    if ((repeatDaysOfWeek_ != 0) || ((GetTimeInterval() > 0) && (GetSnoozeTimes() > 0))) {
        return true;
    } else {
        return false;
    }
}


uint64_t ReminderRequestAlarm::PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext)
{
    if (ignoreRepeat || (repeatDaysOfWeek_)) {
        return GetNextTriggerTime(forceToGetNext);
    } else {
        return INVALID_LONG_LONG_VALUE;
    }
}

uint64_t ReminderRequestAlarm::GetNextTriggerTime(bool forceToGetNext) const
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    ANSR_LOGD("Now: year=%{public}d, mon=%{public}d, day=%{public}d, hour=%{public}d, "
        "min=%{public}d, sec=%{public}d, week=%{public}d, Target: tar_hour=%{public}d, tar_min=%{public}d",
        GetActualTime(TimeTransferType::YEAR, nowTime.tm_year),
        GetActualTime(TimeTransferType::MONTH, nowTime.tm_mon),
        nowTime.tm_mday, nowTime.tm_hour, nowTime.tm_min, nowTime.tm_sec,
        GetActualTime(TimeTransferType::WEEK, nowTime.tm_wday), hour_, minute_);

    struct tm tar;
    tar.tm_year = nowTime.tm_year;
    tar.tm_mon = nowTime.tm_mon;
    tar.tm_mday = nowTime.tm_mday;
    tar.tm_hour = hour_;
    tar.tm_min = minute_;
    tar.tm_sec = 0;
    tar.tm_isdst = -1;

    const time_t target = mktime(&tar);
    if (repeatDaysOfWeek_ > 0) {
        return GetNextDaysOfWeek(now, target);
    }

    time_t nextTriggerTime = 0;
    if (now >= target) {
        if (forceToGetNext) {
            nextTriggerTime = target + 1 * HOURS_PER_DAY * SECONDS_PER_HOUR;
        }
    } else {
        nextTriggerTime = target;
    }
    return GetTriggerTime(now, nextTriggerTime);
}

void ReminderRequestAlarm::SetHour(const uint8_t hour)
{
    hour_ = hour;
}

void ReminderRequestAlarm::SetMinute(const uint8_t minute)
{
    minute_ = minute;
}

uint8_t ReminderRequestAlarm::GetHour() const
{
    return hour_;
}

uint8_t ReminderRequestAlarm::GetMinute() const
{
    return minute_;
}

bool ReminderRequestAlarm::UpdateNextReminder()
{
    ANSR_LOGD("called");
    if (IsRepeatReminder()) {
        uint8_t letfSnoozeTimes = GetSnoozeTimesDynamic();
        if ((letfSnoozeTimes > 0) && (GetTimeInterval() > 0)) {
            ANSR_LOGI("Left times: %{public}d, update next triggerTime", GetSnoozeTimesDynamic());
            SetTriggerTimeInMilli(GetTriggerTimeInMilli() + GetTimeInterval() * MILLI_SECONDS);
            SetSnoozeTimesDynamic(--letfSnoozeTimes);
        } else {
            SetSnoozeTimesDynamic(GetSnoozeTimes());
            if (repeatDaysOfWeek_ == 0) {
                ANSR_LOGI("No need to update next triggerTime");
                SetExpired(true);
                return false;
            }
            uint64_t nextTriggerTime = GetNextTriggerTime(true);
            if (nextTriggerTime != INVALID_LONG_LONG_VALUE) {
                ANSR_LOGI("Set next trigger time successful, reset dynamic snoozeTimes");
                SetTriggerTimeInMilli(nextTriggerTime);
            } else {
                ANSR_LOGW("Set reminder to expired");
                SetExpired(true);
                return false;
            }
        }
        return true;
    } else {
        ANSR_LOGD("Single time reminder, not need to update next trigger time");
        SetSnoozeTimesDynamic(GetSnoozeTimes());
        SetExpired(true);
        return false;
    }
}

bool ReminderRequestAlarm::Marshalling(Parcel &parcel) const
{
    return WriteParcel(parcel);
}

bool ReminderRequestAlarm::WriteParcel(Parcel &parcel) const
{
    if (ReminderRequest::WriteParcel(parcel)) {
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, hour_, "hour");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, minute_, "minute");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, repeatDaysOfWeek_, "repeatDaysOfWeek");
        return true;
    }
    return false;
}

ReminderRequestAlarm *ReminderRequestAlarm::Unmarshalling(Parcel &parcel)
{
    ANSR_LOGD("called");
    auto objptr = new (std::nothrow) ReminderRequestAlarm();
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

bool ReminderRequestAlarm::ReadFromParcel(Parcel &parcel)
{
    if (ReminderRequest::ReadFromParcel(parcel)) {
        READ_UINT8_RETURN_FALSE_LOG(parcel, hour_, "hour");
        READ_UINT8_RETURN_FALSE_LOG(parcel, minute_, "minute");
        READ_UINT8_RETURN_FALSE_LOG(parcel, repeatDaysOfWeek_, "repeatDaysOfWeek");

        ANSR_LOGD("hour_=%{public}d, minute_=%{public}d", hour_, minute_);
        return true;
    }
    return false;
}
}
}