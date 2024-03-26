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

#include "reminder_request_calendar.h"

#include "ans_log_wrapper.h"
#include "reminder_table.h"
#include "reminder_table_old.h"
#include "reminder_store.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
const uint8_t ReminderRequestCalendar::MAX_MONTHS_OF_YEAR = 12;
const uint8_t ReminderRequestCalendar::MAX_DAYS_OF_MONTH = 31;
const uint8_t ReminderRequestCalendar::JANUARY = 1;
const uint8_t ReminderRequestCalendar::DECEMBER = 12;
const uint8_t ReminderRequestCalendar::DEFAULT_SNOOZE_TIMES = 3;

const uint8_t ReminderRequestCalendar::DAY_ARRAY[12]    = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
const uint8_t ReminderRequestCalendar::FEBRUARY         = 2;
const uint8_t ReminderRequestCalendar::LEAP_MONTH       = 29;
const uint8_t ReminderRequestCalendar::NON_LEAP_MONTH   = 28;
const uint16_t ReminderRequestCalendar::SOLAR_YEAR      = 400;
const uint8_t ReminderRequestCalendar::LEAP_PARAM_MIN   = 4;
const uint8_t ReminderRequestCalendar::LEAP_PARAM_MAX   = 100;

ReminderRequestCalendar::ReminderRequestCalendar(const tm &dateTime, const std::vector<uint8_t> &repeatMonths,
    const std::vector<uint8_t> &repeatDays, const std::vector<uint8_t> &daysOfWeek)
    : ReminderRequest(ReminderRequest::ReminderType::CALENDAR)
{
    // 1. record the information which designated by user at first time.
    firstDesignateYear_ = static_cast<uint16_t>(GetActualTime(TimeTransferType::YEAR, dateTime.tm_year));
    firstDesignateMonth_ = static_cast<uint8_t>(GetActualTime(TimeTransferType::MONTH, dateTime.tm_mon));
    firstDesignateDay_ = dateTime.tm_mday;
    SetRepeatMonths(repeatMonths);
    SetRepeatDaysOfMonth(repeatDays);
    SetRepeatDaysOfWeek(true, daysOfWeek);
    SetSnoozeTimes(DEFAULT_SNOOZE_TIMES);

    // 2. should SetNextTriggerTime() after constructor
    InitDateTime(dateTime);
}

ReminderRequestCalendar::ReminderRequestCalendar(const ReminderRequestCalendar &other) : ReminderRequest(other)
{
    dateTime_ = other.dateTime_;
    endDateTime = other.endDateTime_;
    firstDesignateYear_ = other.firstDesignateYear_;
    firstDesignateMonth_ = other.firstDesignateMonth_;
    firstDesignateDay_ = other.firstDesignateDay_;
    year_ = other.year_;
    month_ = other.month_;
    day_ = other.day_;
    hour_ = other.hour_;
    minute_ = other.minute_;
    second_ = other.second_;
    repeatMonth_ = other.repeatMonth_;
    repeatDay_ = other.repeatDay_;
    repeatDaysOfWeek_ = other.repeatDaysOfWeek_;
    rruleWantAgentInfo_ = other.rruleWantAgentInfo_;
    durationTime_ = other.durationTime_;
}

void ReminderRequestCalendar::SetRRuleWantAgentInfo(const std::shared_ptr<WantAgentInfo> &wantAgentInfo)
{
    rruleWantAgentInfo_ = wantAgentInfo;
}

std::shared_ptr<ReminderRequest::WantAgentInfo> ReminderRequestCalendar::GetRRuleWantAgentInfo()
{
    return rruleWantAgentInfo_;
}

bool ReminderRequestCalendar::SetNextTriggerTime()
{
    hour_ = static_cast<uint8_t>(dateTime_.tm_hour);
    minute_ = static_cast<uint8_t>(dateTime_.tm_min);
    uint64_t nextTriggerTime = INVALID_LONG_LONG_VALUE;
    if ((nextTriggerTime = GetNextTriggerTime()) != INVALID_LONG_LONG_VALUE) {
        time_t target = static_cast<time_t>(nextTriggerTime / MILLI_SECONDS);
        (void)localtime_r(&target, &dateTime_);
    } else {
        ANSR_LOGW("Not exist next trigger time, please check the param of ReminderRequestCalendar constructor.");
        return false;
    }

    // set the time information (used to transfer to proxy service) which is decided to trigger firstly.
    year_ = static_cast<uint16_t>(GetActualTime(TimeTransferType::YEAR, dateTime_.tm_year));
    month_ = static_cast<uint8_t>(GetActualTime(TimeTransferType::MONTH, dateTime_.tm_mon));
    day_ = static_cast<uint8_t>(dateTime_.tm_mday);
    second_ = 0;
    SetTriggerTimeInMilli(nextTriggerTime);
    return true;
}

uint8_t ReminderRequestCalendar::GetDaysOfMonth(const uint16_t &year, const uint8_t &month)
{
    uint8_t days;
    if (month == FEBRUARY) {
        days = ((((year % LEAP_PARAM_MIN == 0) && (year % LEAP_PARAM_MAX != 0)) || (year % SOLAR_YEAR == 0))
            ? LEAP_MONTH : NON_LEAP_MONTH);
    } else {
        days = DAY_ARRAY[month - 1];
    }
    return days;
}

uint8_t ReminderRequestCalendar::GetNextDay(
    const uint16_t &settedYear, const uint8_t &settedMonth, const tm &now, const tm &target) const
{
    uint32_t repeatDayTmp = repeatDay_;
    uint8_t daysOfSpecialMonth = GetDaysOfMonth(settedYear, settedMonth);
    uint8_t setDayTmp = INVALID_U8_VALUE;
    for (uint8_t i = 1; i <= daysOfSpecialMonth; i++) {
        if ((repeatDayTmp & (1 << (i - 1))) > 0) {
            struct tm setTime;
            setTime.tm_year = GetCTime(TimeTransferType::YEAR, settedYear);
            setTime.tm_mon = GetCTime(TimeTransferType::MONTH, settedMonth);
            setTime.tm_mday = static_cast<int>(i);
            setTime.tm_hour = target.tm_hour;
            setTime.tm_min = target.tm_min;
            setTime.tm_sec = target.tm_sec;
            setTime.tm_isdst = -1;

            struct tm nowTime;
            nowTime.tm_year = now.tm_year;
            nowTime.tm_mon = now.tm_mon;
            nowTime.tm_mday = now.tm_mday;
            nowTime.tm_hour = now.tm_hour;
            nowTime.tm_min = now.tm_min;
            nowTime.tm_sec = now.tm_sec;
            nowTime.tm_isdst = -1;

            if (mktime(&nowTime) >= mktime(&setTime)) {
                continue;
            } else {
                setDayTmp = i;
                return setDayTmp;
            }
        }
    }
    return setDayTmp;
}

uint64_t ReminderRequestCalendar::GetNextTriggerTime() const
{
    uint64_t triggerTimeInMilli = INVALID_LONG_LONG_VALUE;
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    nowTime.tm_sec = 0;
    struct tm tarTime;
    tarTime.tm_year = GetCTime(TimeTransferType::YEAR, firstDesignateYear_);
    tarTime.tm_mon = GetCTime(TimeTransferType::MONTH, firstDesignateMonth_);
    tarTime.tm_mday = firstDesignateDay_;
    tarTime.tm_hour = hour_;
    tarTime.tm_min = minute_;
    tarTime.tm_sec = 0;
    tarTime.tm_isdst = -1;
    const time_t target = mktime(&tarTime);
    ANSR_LOGD("Now time is: %{public}s", GetDateTimeInfo(now).c_str());
    if (repeatMonth_ > 0 && repeatDay_ > 0) {
        triggerTimeInMilli = GetNextTriggerTimeAsRepeatReminder(nowTime, tarTime);
    } else if (repeatDaysOfWeek_ > 0 && (target <= now)) {
        nowTime.tm_hour = tarTime.tm_hour;
        nowTime.tm_min = tarTime.tm_min;
        nowTime.tm_sec = tarTime.tm_sec;
        nowTime.tm_isdst = tarTime.tm_isdst;
        const time_t tar = mktime(&nowTime);
        triggerTimeInMilli = GetNextDaysOfWeek(now, tar);
    } else {
        ANSR_LOGD("tarTime: %{public}d-%{public}d-%{public}d %{public}d:%{public}d:%{public}d",
            tarTime.tm_year, tarTime.tm_mon, tarTime.tm_mday, tarTime.tm_hour, tarTime.tm_min, tarTime.tm_sec);
        if (target == -1) {
            ANSR_LOGW("mktime return error.");
        }
        if (now < target) {
            triggerTimeInMilli = ReminderRequest::GetDurationSinceEpochInMilli(target);
            ANSR_LOGD("Next calendar time:%{public}s", GetDateTimeInfo(target).c_str());
        }
    }
    return triggerTimeInMilli;
}

uint64_t ReminderRequestCalendar::GetNextTriggerTimeAsRepeatReminder(const tm &nowTime, const tm &tarTime) const
{
    uint64_t triggerTimeInMilli = INVALID_LONG_LONG_VALUE;
    uint16_t setYear = static_cast<uint16_t>(GetActualTime(TimeTransferType::YEAR, nowTime.tm_year));
    uint8_t setMonth = INVALID_U8_VALUE;
    uint8_t setDay = INVALID_U8_VALUE;
    uint8_t beginMonth = static_cast<uint8_t>(GetActualTime(TimeTransferType::MONTH, nowTime.tm_mon));
    uint8_t count = 1;
    uint16_t repeatMonthTmp = repeatMonth_;
    for (uint8_t i = beginMonth; i < (MAX_MONTHS_OF_YEAR + beginMonth + 1); i++) {
        if ((repeatMonthTmp & (1 << ((i - 1) % MAX_MONTHS_OF_YEAR))) > 0) {
            setMonth = (i % MAX_MONTHS_OF_YEAR);
            setMonth = setMonth == 0 ? DECEMBER : setMonth;
            if (count != 1) {
                setYear = setMonth <= beginMonth ? setYear + 1 : setYear;
            }
            setDay = GetNextDay(setYear, setMonth, nowTime, tarTime);
        }
        if (setDay != INVALID_U8_VALUE) {
            break;
        }
        count++;
    }
    if ((triggerTimeInMilli = GetTimeInstantMilli(setYear, setMonth, setDay, hour_, minute_, second_))
        != INVALID_LONG_LONG_VALUE) {
        ANSR_LOGD("Next calendar time:%{public}hu/%{public}hhu/%{public}hhu %{public}hhu:%{public}hhu:%{public}hhu",
            setYear, setMonth, setDay, hour_, minute_, second_);
    }
    return triggerTimeInMilli;
}

uint64_t ReminderRequestCalendar::GetTimeInstantMilli(
    uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) const
{
    struct tm tar;
    tar.tm_year = GetCTime(TimeTransferType::YEAR, year);
    tar.tm_mon =  GetCTime(TimeTransferType::MONTH, month);
    tar.tm_mday = static_cast<int>(day);
    tar.tm_hour = static_cast<int>(hour);
    tar.tm_min = static_cast<int>(minute);
    tar.tm_sec = static_cast<int>(second);
    tar.tm_isdst = -1;

    ANSR_LOGD("tar: %{public}d-%{public}d-%{public}d %{public}d:%{public}d:%{public}d",
        tar.tm_year, tar.tm_mon, tar.tm_mday, tar.tm_hour, tar.tm_min, tar.tm_sec);
    const time_t target = mktime(&tar);
    if (target == -1) {
        ANSR_LOGW("mktime return error.");
        return INVALID_LONG_LONG_VALUE;
    }
    return ReminderRequest::GetDurationSinceEpochInMilli(target);
}

void ReminderRequestCalendar::InitDateTime()
{
    dateTime_.tm_year = GetCTime(TimeTransferType::YEAR, year_);
    dateTime_.tm_mon = GetCTime(TimeTransferType::MONTH, month_);
    dateTime_.tm_mday = static_cast<int>(day_);
    dateTime_.tm_hour = static_cast<int>(hour_);
    dateTime_.tm_min = static_cast<int>(minute_);
    dateTime_.tm_sec = static_cast<int>(second_);
    dateTime_.tm_isdst = -1;
}

void ReminderRequestCalendar::InitDateTime(const tm &dateTime)
{
    dateTime_.tm_year = dateTime.tm_year;
    dateTime_.tm_mon = dateTime.tm_mon;
    dateTime_.tm_mday = dateTime.tm_mday;
    dateTime_.tm_hour = dateTime.tm_hour;
    dateTime_.tm_min = dateTime.tm_min;
    dateTime_.tm_sec = dateTime.tm_sec;
    dateTime_.tm_isdst = -1;
}

bool ReminderRequestCalendar::IsRepeatReminder() const
{
    return (repeatMonth_ > 0 && repeatDay_ > 0) || (repeatDaysOfWeek_ > 0)
        || (GetTimeInterval() > 0 && GetSnoozeTimes() > 0);
}

bool ReminderRequestCalendar::IsRepeatMonth(uint8_t month) const
{
    if (month > MAX_MONTHS_OF_YEAR) {
        return false;
    }
    return (repeatMonth_ & (1 << (month - 1))) > 0;
}

bool ReminderRequestCalendar::IsRepeatDay(uint8_t day) const
{
    if (day > MAX_DAYS_OF_MONTH) {
        return false;
    }
    return (repeatDay_ & (1 << (day - 1))) > 0;
}

void ReminderRequestCalendar::SetDay(const uint8_t &day, const bool &isSet)
{
    if (day < 1 || day > MAX_DAYS_OF_MONTH) {
        return;
    }
    if (isSet) {
        repeatDay_ |= 1 << (day - 1);
    } else {
        repeatDay_ &= ~(1 << (day - 1));
    }
}

void ReminderRequestCalendar::SetMonth(const uint8_t &month, const bool &isSet)
{
    if (month < JANUARY || month > DECEMBER) {
        return;
    }
    if (isSet) {
        repeatMonth_ |= 1 << (month - 1);
    } else {
        repeatMonth_ &= ~ (1 << (month - 1));
    }
}

void ReminderRequestCalendar::SetRepeatMonths(const std::vector<uint8_t> &repeatMonths)
{
    if (repeatMonths.size() > MAX_MONTHS_OF_YEAR) {
        ANSR_LOGW("The length of repeat months array should not larger than %{public}hhu", MAX_MONTHS_OF_YEAR);
        return;
    }
    repeatMonth_ = 0;
    for (auto it = repeatMonths.begin(); it != repeatMonths.end(); ++it) {
        SetMonth((*it), true);
    }
}

void ReminderRequestCalendar::SetRepeatDaysOfMonth(const std::vector<uint8_t> &repeatDays)
{
    if (repeatDays.size() > MAX_DAYS_OF_MONTH) {
        ANSR_LOGW("The length of repeat days array should not larger than %{public}hhu", MAX_DAYS_OF_MONTH);
        return;
    }
    repeatDay_ = 0;
    for (auto it = repeatDays.begin(); it != repeatDays.end(); ++it) {
        SetDay((*it), true);
    }
}

void ReminderRequestCalendar::setDurationTime(const tm &dateTime, const tm &endDateTime)
{
    uint64_t beginTime = GetDateTime();
    uint64_t endTime = GetEndDateTime();
    if (endTime == INVALID_LONG_LONG_VALUE) {
        durationTime_ = 0;
    }
    durationTime_ = endTime - beginTime;
}

uint64_t ReminderRequestCalendar::setDurationTime() const
{
    return durationTime_;
}

std::vector<uint8_t> ReminderRequestCalendar::GetRepeatMonths() const
{
    std::vector<uint8_t> repeatMonths;
    for (int32_t i = 0; i < MAX_MONTHS_OF_YEAR; i++) {
        if (IsRepeatMonth(i + 1)) {
            repeatMonths.push_back(i + 1);
        }
    }
    return repeatMonths;
}

std::vector<uint8_t> ReminderRequestCalendar::GetRepeatDays() const
{
    std::vector<uint8_t> repeatDays;
    for (int32_t i = 0; i < MAX_DAYS_OF_MONTH; i++) {
        if (IsRepeatDay(i + 1)) {
            repeatDays.push_back(i + 1);
        }
    }
    return repeatDays;
}

bool ReminderRequestCalendar::UpdateNextReminder()
{
    ANSR_LOGD("UpdateNextReminder calendar time");
    if (!IsRepeatReminder()) {
        ANSR_LOGI("No need to update next trigger time as it is an one-time reminder.");
        SetSnoozeTimesDynamic(GetSnoozeTimes());
        SetExpired(true);
        return false;
    }
    uint8_t leftSnoozeTimes = GetSnoozeTimesDynamic();
    if (leftSnoozeTimes > 0 && (GetTimeInterval() > 0)) {
        ANSR_LOGI("Left snooze times: %{public}d, update next triggerTime", leftSnoozeTimes);
        SetTriggerTimeInMilli(GetTriggerTimeInMilli() + GetTimeInterval() * MILLI_SECONDS);
        SetSnoozeTimesDynamic(--leftSnoozeTimes);
    } else {
        SetSnoozeTimesDynamic(GetSnoozeTimes());
        if ((repeatMonth_ == 0 || repeatDay_ == 0) && (repeatDaysOfWeek_ == 0)) {
            ANSR_LOGI("Not a day repeat reminder, no need to update to next trigger time.");
            SetExpired(true);
            return false;
        } else {
            uint64_t nextTriggerTime = GetNextTriggerTime();
            if (nextTriggerTime != INVALID_LONG_LONG_VALUE) {
                ANSR_LOGI("Set next trigger time successful, reset dynamic snoozeTimes");
                SetTriggerTimeInMilli(nextTriggerTime);
            } else {
                ANSR_LOGW("Set next trigger time invalidate");
                SetExpired(true);
                return false;
            }
        }
    }
    return true;
}

uint64_t ReminderRequestCalendar::PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext) const
{
    if (ignoreRepeat || (repeatMonth_ > 0 && repeatDay_ > 0) || (repeatDaysOfWeek_ > 0)) {
        return GetNextTriggerTime();
    } else {
        return INVALID_LONG_LONG_VALUE;
    }
}

bool ReminderRequestCalendar::Marshalling(Parcel &parcel) const
{
    if (ReminderRequest::Marshalling(parcel)) {
        // write int
        WRITE_UINT16_RETURN_FALSE_LOG(parcel, year_, "year");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, month_, "month");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, day_, "day");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, hour_, "hour");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, minute_, "minute");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, second_, "second");
        WRITE_UINT16_RETURN_FALSE_LOG(parcel, repeatMonth_, "repeatMonth");
        WRITE_UINT32_RETURN_FALSE_LOG(parcel, repeatDay_, "repeatDay");
        WRITE_UINT64_RETURN_FALSE_LOG(parcel, durationTime_, "durationTime");
        WRITE_UINT16_RETURN_FALSE_LOG(parcel, firstDesignateYear_, "firstDesignateYear");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, firstDesignateMonth_, "firstDesignateMonth");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, firstDesignateDay_, "firstDesignateDay");
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, repeatDaysOfWeek_, "repeatDaysOfWeek");

        bool rruleFlag = rruleWantAgentInfo_ == nullptr ? 0 : 1;
        WRITE_BOOL_RETURN_FALSE_LOG(parcel, rruleFlag, "rruleFlag");
        if (rruleWantAgentInfo_ != nullptr) {
            WRITE_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->pkgName, "rruleWantAgentInfo's pkgName");
            WRITE_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->abilityName, "rruleWantAgentInfo's abilityName");
            WRITE_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->uri, "rruleWantAgentInfo's uri");
        }
        return true;
    }
    return false;
}

ReminderRequestCalendar *ReminderRequestCalendar::Unmarshalling(Parcel &parcel)
{
    ANSR_LOGD("New calendar");
    auto objptr = new (std::nothrow) ReminderRequestCalendar();
    if (objptr == nullptr) {
        ANS_LOGE("Failed to create reminder calendar due to no memory.");
        return objptr;
    }
    if (!objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool ReminderRequestCalendar::ReadFromParcel(Parcel &parcel)
{
    if (ReminderRequest::ReadFromParcel(parcel)) {
        // read int
        READ_UINT16_RETURN_FALSE_LOG(parcel, year_, "year");
        READ_UINT8_RETURN_FALSE_LOG(parcel, month_, "month");
        READ_UINT8_RETURN_FALSE_LOG(parcel, day_, "day");
        READ_UINT8_RETURN_FALSE_LOG(parcel, hour_, "hour");
        READ_UINT8_RETURN_FALSE_LOG(parcel, minute_, "minute");
        READ_UINT8_RETURN_FALSE_LOG(parcel, second_, "second");
        READ_UINT16_RETURN_FALSE_LOG(parcel, repeatMonth_, "repeatMonth");
        READ_UINT32_RETURN_FALSE_LOG(parcel, repeatDay_, "repeatDay");
        READ_UINT64_RETURN_FALSE_LOG(parcel, durationTime_, "durationTime");

        InitDateTime();

        READ_UINT16_RETURN_FALSE_LOG(parcel, firstDesignateYear_, "firstDesignateYear");
        READ_UINT8_RETURN_FALSE_LOG(parcel, firstDesignateMonth_, "firstDesignateMonth");
        READ_UINT8_RETURN_FALSE_LOG(parcel, firstDesignateDay_, "firstDesignateDay");
        READ_UINT8_RETURN_FALSE_LOG(parcel, repeatDaysOfWeek_, "repeatDaysOfWeek");

        bool rruleFlag = false;
        READ_BOOL_RETURN_FALSE_LOG(parcel, rruleFlag, "rruleFlag");
        if (rruleFlag) {
            rruleWantAgentInfo_ = std::make_shared<WantAgentInfo>();
            READ_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->pkgName, "rruleWantAgentInfo's pkgName");
            READ_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->abilityName, "rruleWantAgentInfo's abilityName");
            READ_STRING_RETURN_FALSE_LOG(parcel, rruleWantAgentInfo_->uri, "rruleWantAgentInfo's uri");
        }
        return true;
    }
    return false;
}

void ReminderRequestCalendar::RecoverFromOldVersion(const std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    ReminderRequest::RecoverFromOldVersion(resultSet);

    // repeatDay
    repeatDay_ = static_cast<uint32_t>(RecoverInt64FromDb(resultSet, ReminderTable::REPEAT_DAYS,
        DbRecoveryType::INT));

    // repeatMonth
    repeatMonth_ =
        static_cast<uint16_t>(RecoverInt64FromDb(resultSet, ReminderTable::REPEAT_MONTHS,
            DbRecoveryType::INT));

    // firstDesignateYear
    firstDesignateYear_ =
        static_cast<uint16_t>(RecoverInt64FromDb(resultSet, ReminderTable::FIRST_DESIGNATE_YEAR,
            DbRecoveryType::INT));

    // firstDesignateMonth
    firstDesignateMonth_ =
        static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::FIRST_DESIGNATE_MONTH,
            DbRecoveryType::INT));

    // firstDesignateDay
    firstDesignateDay_ =
        static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::FIRST_DESIGNATE_DAY,
            DbRecoveryType::INT));

    // year
    year_ = static_cast<uint16_t>(RecoverInt64FromDb(resultSet, ReminderTable::CALENDAR_YEAR,
        DbRecoveryType::INT));

    // month
    month_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::CALENDAR_MONTH,
        DbRecoveryType::INT));

    // day
    day_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::CALENDAR_DAY,
        DbRecoveryType::INT));

    // hour
    hour_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::CALENDAR_HOUR,
        DbRecoveryType::INT));

    // minute
    minute_ = static_cast<uint8_t>(RecoverInt64FromDb(resultSet, ReminderTable::CALENDAR_MINUTE,
        DbRecoveryType::INT));
}

void ReminderRequestCalendar::RecoverFromDb(const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null");
        return;
    }
    ReminderStore::GetUInt16Val(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_YEAR, firstDesignateYear_);
    ReminderStore::GetUInt8Val(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_MONTH, firstDesignateMonth_);
    ReminderStore::GetUInt8Val(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_DAY, firstDesignateDay_);

    uint64_t dateTime;
    ReminderStore::GetUInt64Val(resultSet, ReminderCalendarTable::CALENDAR_DATE_TIME, dateTime);
    SetDateTime(dateTime);

    uint64_t endDateTime;
    ReminderStore::GetUInt64Val(resultSet, ReminderCalendarTable::CALENDAR_END_DATE_TIME, endDateTime);
    setEndDateTime(endDateTime);

    int32_t repeatDay;
    ReminderStore::GetInt32Val(resultSet, ReminderCalendarTable::REPEAT_DAYS, repeatDay);
    repeatDay_ = static_cast<uint32_t>(repeatDay);

    ReminderStore::GetUInt16Val(resultSet, ReminderCalendarTable::REPEAT_MONTHS, repeatMonth_);
    ReminderStore::GetUInt8Val(resultSet, ReminderCalendarTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek_);

    std::string rruleWantAgent;
    ReminderStore::GetStringVal(resultSet, ReminderCalendarTable::RRULE_WANT_AGENT, rruleWantAgent);
    DeserializationRRule(rruleWantAgent);

    std::string excludeDates;
    ReminderStore::GetStringVal(resultSet, ReminderCalendarTable::EXCLUDE_DATES, excludeDates);
}

void ReminderRequestCalendar::AppendValuesBucket(const sptr<ReminderRequest> &reminder,
    const sptr<NotificationBundleOption> &bundleOption, NativeRdb::ValuesBucket &values)
{
    uint16_t firstDesignateYear = 0;
    uint8_t firstDesignateMonth = 0;
    uint8_t firstDesignateDay = 0;
    uint64_t dateTime = 0;
    uint32_t repeatDay = 0;
    uint16_t repeatMonth = 0;
    uint8_t repeatDaysOfWeek = 0;
    uint64_t durationTime = 0;
    std::string rruleWantAgent;
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        if (calendar != nullptr) {
            repeatDay = calendar->GetRepeatDay();
            repeatMonth = calendar->GetRepeatMonth();
            firstDesignateYear = calendar->GetFirstDesignateYear();
            firstDesignateMonth = calendar->GetFirstDesignageMonth();
            firstDesignateDay = calendar->GetFirstDesignateDay();
            dateTime = calendar->GetDateTime();
            repeatDaysOfWeek = calendar->GetRepeatDaysOfWeek();
            durationTime = calendar->GetDurationTime();
            rruleWantAgent = calendar->SerializationRRule();
        }
    }
    values.PutInt(ReminderCalendarTable::REMINDER_ID, reminder->GetReminderId());
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_YEAR, firstDesignateYear);
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_MONTH, firstDesignateMonth);
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_DAY, firstDesignateDay);
    values.PutLong(ReminderCalendarTable::CALENDAR_DATE_TIME, dateTime);
    values.PutLong(ReminderCalendarTable::CALENDAR_END_DATE_TIME, 0);  // next
    values.PutInt(ReminderCalendarTable::REPEAT_DAYS, repeatDay);
    values.PutInt(ReminderCalendarTable::REPEAT_MONTHS, repeatMonth);
    values.PutInt(ReminderCalendarTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
    values.PutString(ReminderCalendarTable::RRULE_WANT_AGENT, rruleWantAgent);
    values.PutString(ReminderCalendarTable::EXCLUDE_DATES, "");  // next
}

bool ReminderRequestCalendar::CheckCalenderIsExpired(const uint64_t oriTriggerTime, const uint64_t now,
    const uint64_t durationTime)
{
    uint64_t newEndTime = oriTriggerTime + durationTime;
    if (now <= newEndTime && now >= oriTriggerTime) {
        return true;
    }
    if (newEndTime < now) {
        return false;
    }
    return false;
}

bool ReminderRequest::HandleSysTimeChange(uint64_t oriTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    uint64_t now = GetNowInstantMilli();
    if (now == 0) {
        ANSR_LOGE("get now time failed.");
        return false;
    }
    if (oriTriggerTime == 0 && optTriggerTime < now) {
        ANSR_LOGW("trigger time is less than now time.");
        return false;
    }
    bool showImmediately = false;
    uint64_t durationTime = GetDurationTime();
    showImmediately = CanDisplayTmmediatelySys(oriTriggerTime, optTriggerTime, now);
    return showImmediately;
}

bool ReminderRequest::HandleTimeZoneChange(
    uint64_t oldZoneTriggerTime, uint64_t newZoneTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    uint64_t now = GetNowInstantMilli();
    ANSR_LOGD("Handle timezone change, old:%{public}" PRIu64 ", new:%{public}" PRIu64 "",
        oldZoneTriggerTime, newZoneTriggerTime);
    if (oldZoneTriggerTime == newZoneTriggerTime) {
        return false;
    }
    bool showImmediately = false;
    uint64_t durationTime = GetDurationTime();
    if (!CheckCalenderIsExpired(oriTriggerTime, now, durationTime)) {
        return false;
    }
    showImmediately = CanDisplayTmmediatelyTimeZone(oldZoneTriggerTime, newZoneTriggerTime, optTriggerTime);
    return showImmediately;
}

void ReminderRequestCalendar::SetDateTime(const uint64_t time)
{
    time_t t = static_cast<time_t>(time / MILLI_SECONDS);
    struct tm dateTime;
    (void)localtime_r(&t, &dateTime);

    year_ = static_cast<uint16_t>(GetActualTime(TimeTransferType::YEAR, dateTime.tm_year));
    month_ = static_cast<uint8_t>(GetActualTime(TimeTransferType::MONTH, dateTime.tm_mon));
    day_ = static_cast<uint8_t>(dateTime.tm_mday);
    hour_ = static_cast<uint8_t>(dateTime.tm_hour);
    minute_ = static_cast<uint8_t>(dateTime.tm_min);
    second_ = static_cast<uint8_t>(dateTime.tm_sec);
}

void ReminderRequestCalendar::SetEndDateTime(const uint64_t time)
{
    time_t t = static_cast<time_t>(time / MILLI_SECONDS);
    struct tm endDateTime;
    (void)localtime_r(&t, &endDateTime);

    endYear_ = static_cast<uint16_t>(GetActualTime(TimeTransferType::YEAR, endDateTime.tm_year));
    endMonth_ = static_cast<uint8_t>(GetActualTime(TimeTransferType::MONTH, endDateTime.tm_mon));
    endDay_ = static_cast<uint8_t>(endDateTime.tm_mday);
    endHour_ = static_cast<uint8_t>(endDateTime.tm_hour);
    endMinute_ = static_cast<uint8_t>(endDateTime.tm_min);
    endSecond_ = static_cast<uint8_t>(endDateTime.tm_sec);
}

uint64_t ReminderRequestCalendar::GetDateTime()
{
    struct tm dateTime;
    dateTime.tm_year = GetCTime(TimeTransferType::YEAR, year_);
    dateTime.tm_mon = GetCTime(TimeTransferType::MONTH, month_);
    dateTime.tm_mday = static_cast<int>(day_);
    dateTime.tm_hour = static_cast<int>(hour_);
    dateTime.tm_min = static_cast<int>(minute_);
    dateTime.tm_sec = static_cast<int>(second_);
    dateTime.tm_isdst = -1;

    time_t time = mktime(&dateTime);
    return GetDurationSinceEpochInMilli(time);
}

uint64_t ReminderRequestCalendar::GetEndDateTime()
{
    struct tm endDateTime;
    endDateTime.tm_year = GetCTime(TimeTransferType::YEAR, endYear_);
    endDateTime.tm_mon = GetCTime(TimeTransferType::MONTH, endMonth_);
    endDateTime.tm_mday = static_cast<int>(endDay_);
    endDateTime.tm_hour = static_cast<int>(endHour_);
    endDateTime.tm_min = static_cast<int>(endMinute_);
    endDateTime.tm_sec = static_cast<int>(endSecond_);
    endDateTime.tm_isdst = -1;

    time_t time = mktime(&endDateTime);
    return GetDurationSinceEpochInMilli(time);
}

std::string ReminderRequestCalendar::SerializationRRule()
{
    constexpr int32_t INDENT = -1;
    if (rruleWantAgentInfo_ == nullptr) {
        return "";
    }
    nlohmann::json root;
    root["pkgName"] = rruleWantAgentInfo_->pkgName;
    root["abilityName"] = rruleWantAgentInfo_->abilityName;
    root["uri"] = rruleWantAgentInfo_->uri;
    std::string str = root.dump(INDENT, ' ', false, nlohmann::json::error_handler_t::replace);
    return str;
}

void ReminderRequestCalendar::DeserializationRRule(const std::string& str)
{
    if (str.empty()) {
        return;
    }
    nlohmann::json root = nlohmann::json::parse(str);
    if (!root.contains("pkgName") || !root["pkgName"].is_string() ||
        !root.contains("abilityName") || !root["abilityName"].is_string() ||
        !root.contains("uri") || !root["uri"].is_string()) {
        return;
    }

    rruleWantAgentInfo_ = std::make_shared<WantAgentInfo>();
    rruleWantAgentInfo_->pkgName = root["pkgName"].get<std::string>();
    rruleWantAgentInfo_->abilityName = root["abilityName"].get<std::string>();
    rruleWantAgentInfo_->uri = root["uri"].get<std::string>();
}
}
}
