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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CALENDAR_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CALENDAR_H

#include "reminder_request.h"

namespace OHOS {
namespace Notification {
class ReminderRequestCalendar : public ReminderRequest {
public:
    /**
     * @brief A {@link ReminderRequest} child class used for creating reminders of calendar clocks.
     *
     * @note The params must meet the following conditions.
     * otherwise the application may crash due to an illegal parameter exception.
     * <ul>
     * <li> The length of repeatMonths vectory cannot exceed 12. </li>
     * <li> The length of repeateDays vectory cannot exceed 31. </li>
     * <li> There must be at least one valid reminder time. Ensure that the time specified by dateTime
     * does not expired, or repeatMonths and repeateDays are valid. </li>
     * </ul>
     *
     * The repeateMonths and repeatDays must both be set to implements repeated reminders.
     * By default, this reminder is not snoozed. You can call {@link SetTimeInterval} to
     * set the snooze interval.
     *
     * @param dateTime Indicates the date and time when this calendar event reminder will be triggered.
     *                 The time is accurate to minute. For example, the value
     *                 {@link LocalDateTime(2021, 3, 3, 16, 15)} indicates that the reminder will be
     *                 triggered at 16:15 on March 3, 2021.
     * @param repeatMonths Indicates the months in which this reminder will be repeated. For example,
     *                     the value {2, 4} indicates that the reminder will be triggered on particular
     *                     days in February and April.
     * @param repeatDays Indicates the days in a month when this reminder will be repeated. For example,
     *                   the value {2, 4} indicates that the reminder will be triggered on the second
     *                   and fourth day of the specific months.
     */
    ReminderRequestCalendar(const tm &dateTime, const std::vector<uint8_t> &repeatMonths,
        const std::vector<uint8_t> &repeatDays, const std::vector<uint8_t> &daysOfWeek);

    /**
     * @brief This constructor should only be used in background proxy service process
     * when reminder instance recovery from database.
     *
     * @param reminderId Indicates reminder id.
     */
    explicit ReminderRequestCalendar(int32_t reminderId) : ReminderRequest(reminderId)
    {
        SetReminderType(ReminderType::CALENDAR);
    };

    explicit ReminderRequestCalendar(const ReminderRequestCalendar &other);
    ReminderRequestCalendar& operator = (const ReminderRequestCalendar &other);
    ~ReminderRequestCalendar() override {}

    void SetRRuleWantAgentInfo(const std::shared_ptr<WantAgentInfo> &wantAgentInfo);

    std::shared_ptr<ReminderRequest::WantAgentInfo> GetRRuleWantAgentInfo();

    void AddExcludeDate(const int64_t date);
    void DelExcludeDates();
    std::vector<int64_t> GetExcludeDates() const;
    bool IsInExcludeDate() const;

    inline uint16_t GetYear() const
    {
        return year_;
    }

    inline uint8_t GetMonth() const
    {
        return month_;
    }

    inline uint8_t GetDay() const
    {
        return day_;
    }

    inline uint8_t GetHour() const
    {
        return hour_;
    }

    inline uint8_t GetMinute() const
    {
        return minute_;
    }

    inline uint8_t GetSecond() const
    {
        return second_;
    }

    inline uint16_t GetFirstDesignateYear() const
    {
        return firstDesignateYear_;
    }

    inline uint16_t GetFirstDesignageMonth() const
    {
        return firstDesignateMonth_;
    }

    inline uint16_t GetFirstDesignateDay() const
    {
        return firstDesignateDay_;
    }

    /**
     * @brief Gets the repeat day.
     */
    uint32_t GetRepeatDay() const
    {
        return repeatDay_;
    }

    /**
     * @brief Gets the repeat month.
     */
    uint16_t GetRepeatMonth() const
    {
        return repeatMonth_;
    }

    /**
     * @brief Gets the start date time.
     */
    uint64_t GetDateTime() const;

    /**
     * @brief Gets the end date time.
     */
    uint64_t GetEndDateTime() const;

    /**
     * @brief Sets the year.
     *
     * @param year Indicates the year.
     */
    void SetYear(const uint16_t year);

    /**
     * @brief Sets the month.
     *
     * @param month Indicates the month.
     */
    void SetMonth(const uint8_t month);

    /**
     * @brief Sets the day.
     *
     * @param day Indicates the day.
     */
    void SetDay(const uint8_t day);

    /**
     * @brief Sets the hour.
     *
     * @param hour Indicates the hour.
     */
    void SetHour(const uint8_t hour);

    /**
     * @brief Sets the minute.
     *
     * @param minute Indicates the minute.
     */
    void SetMinute(const uint8_t minute);

    /**
     * @brief Sets the repeat day.
     *
     * @param repeatDay Indicates the repeat day.
     */
    void SetRepeatDay(const uint32_t repeatDay);

    /**
     * @brief Sets the repeat month.
     *
     * @param repeatMonth Indicates the repeat month.
     */
    void SetRepeatMonth(const uint16_t repeatMonth);

    /**
     * @brief Sets the first designate year.
     *
     * @param firstDesignateYear Indicates the first designate year.
     */
    void SetFirstDesignateYear(const uint16_t firstDesignateYear);

    /**
     * @brief Sets the first designate month.
     *
     * @param firstDesignateMonth Indicates the first designate month.
     */
    void SetFirstDesignageMonth(const uint16_t firstDesignateMonth);

    /**
     * @brief Sets the first designate day.
     *
     * @param firstDesignateDay Indicates the first designate day.
     */
    void SetFirstDesignateDay(const uint16_t firstDesignateDay);

    /**
     * @brief Sets the hour.
     *
     * @param hour Indicates the hour.
     */
    void SetDateTime(const uint64_t time);

    /**
     * @brief Serialize the rrule to string.
     * Persist to the rdb.
     */
    std::string SerializationRRule();

    /**
     * @brief Deserialize the rrule from string.
     * Recover from the rdb.
     */
    void DeserializationRRule(const std::string& str);

    /**
     * @brief Serialize the exclude date to string.
     * Persist to the rdb.
     */
    std::string SerializationExcludeDates();

    /**
     * @brief Deserialize the exclude date from string.
     * Recover from the rdb.
     */
    void DeserializationExcludeDates(const std::string& str);

    bool InitTriggerTime();

    std::vector<uint8_t> GetRepeatMonths() const;
    std::vector<uint8_t> GetRepeatDays() const;

    virtual bool UpdateNextReminder() override;
    virtual bool OnDateTimeChange() override;

    /**
     * @brief Check reminder request is repeat
     */
    bool IsRepeat() const override;

    /**
     * @brief Check reminder request is in exclude date
     */
    bool CheckExcludeDate() override;

    /**
     * @brief Check rrule want agent, pull up service extension
     */
    bool IsPullUpService() override;

    /**
     * @brief Check need notification reminder. due to system timer.
     * When change system time to later, more than the trigger time, system timer must trigger.
     */
    bool IsNeedNotification() override;

    /**
     * Marshal a reminder object into a Parcel.
     *
     * @param parcel Indicates the Parcel.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the Parcel.
     * @return reminder object.
     */
    static ReminderRequestCalendar *Unmarshalling(Parcel &parcel);

    /**
     * Unmarshal unique properties of alarm from a Parcel.
     *
     * @param parcel Indicates the Parcel.
     * @return true if read parcel success.
     */
    bool ReadFromParcel(Parcel &parcel) override;
    bool WriteParcel(Parcel &parcel) const override;
    bool SetNextTriggerTime() override;

    static uint8_t GetDaysOfMonth(const uint16_t &year, const uint8_t &month);
    bool SetEndDateTime(const uint64_t time);

    /**
     * @brief Sets the start time when the notification was last displayed in the notification bar.
     * When OnDateTimeChange or OnClose, the time will change to next start time if the reminder
     * is repeat, otherwise not changed.
     */
    void SetLastStartDateTime(const uint64_t time);

    /**
     * @brief Get the start time when the notification was last displayed in the notification bar.
     */
    uint64_t GetLastStartDateTime() const;

    ReminderRequestCalendar() : ReminderRequest(ReminderType::CALENDAR) {};

    /**
     * @brief Copy datashare reminder
     */
    void Copy(const sptr<ReminderRequest>& other);

public:
    static constexpr uint8_t MAX_MONTHS_OF_YEAR = 12;
    static constexpr uint8_t MAX_DAYS_OF_MONTH = 31;

protected:
    virtual uint64_t PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext) override;

private:

    uint8_t GetNextDay(const uint16_t &settedYear, const uint8_t &settedMonth, const tm &now, const tm &target) const;
    uint64_t GetNextTriggerTime(const bool updateLast = false);
    uint64_t GetNextTriggerTimeAsRepeatReminder(const tm &nowTime, const tm &tarTime) const;
    uint64_t GetTimeInstantMilli(
        uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second) const;

    /**
     * @brief Init dateTime_ when read from parcel.
     */
    void InitDateTime();
    void InitDateTime(const tm &dateTime);
    bool IsRepeatReminder() const;
    bool IsRepeatMonth(uint8_t month) const;
    bool IsRepeatDay(uint8_t day) const;
    void SetDay(const uint8_t &day, const bool &isSet);
    void SetMonth(const uint8_t &month, const bool &isSet);
    void SetRepeatMonths(const std::vector<uint8_t> &repeatMonths);
    void SetRepeatDaysOfMonth(const std::vector<uint8_t> &repeatDays);
    bool CheckCalenderIsExpired(const uint64_t now);

    /**
     * @brief When OnShow or OnSnooze, need calculate the start time of this alert
     */
    void CalcLastStartDateTime();

    static const uint8_t DEFAULT_SNOOZE_TIMES;

    tm dateTime_ = {
        .tm_sec = 0,
        .tm_min = 0,
        .tm_hour = 0,
        .tm_mday = 1,
        .tm_mon = 0,
        .tm_year = 0,
        .tm_wday = 0,
        .tm_yday = 0,
        .tm_isdst = -1
    };
    uint16_t firstDesignateYear_ {1};
    uint8_t firstDesignateMonth_ {1};
    uint8_t firstDesignateDay_ {1};
    uint16_t year_ {1};
    uint8_t month_ {1};
    uint8_t day_ {1};
    uint8_t hour_ {1};
    uint8_t minute_ {1};
    uint8_t second_ {0};
    uint16_t repeatMonth_ {0};
    uint32_t repeatDay_ {0};

    uint64_t startDateTime_{0};
    uint64_t endDateTime_{0};
    uint64_t durationTime_{0};
    uint64_t lastStartDateTime_{0};

    std::set<int64_t> excludeDates_;

    // repeat calendar
    std::shared_ptr<WantAgentInfo> rruleWantAgentInfo_ = nullptr;
    
private:
    static const uint8_t DAY_ARRAY[12];
    static constexpr uint8_t JANUARY = 1;
    static constexpr uint8_t DECEMBER = 12;
    // if startDateTime < now and now < endDateTime, triggerTime = now + DELAY
    static constexpr uint64_t DEFAULT_DELAY_TIME = 3000;

    // for check leap year
    static constexpr uint8_t FEBRUARY = 2;
    static constexpr uint8_t LEAP_MONTH = 29;
    static constexpr uint8_t NON_LEAP_MONTH = 28;
    static constexpr uint16_t SOLAR_YEAR = 400;
    static constexpr uint8_t LEAP_PARAM_MIN = 4;
    static constexpr uint8_t LEAP_PARAM_MAX = 100;
};
}
}
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CALENDAR_H