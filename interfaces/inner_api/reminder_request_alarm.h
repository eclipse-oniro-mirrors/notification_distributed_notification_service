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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ALARM_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ALARM_H

#include "reminder_request.h"

#include <vector>

namespace OHOS {
namespace Notification {
class ReminderRequestAlarm : public ReminderRequest {
public:
    /**
     * @brief A {@link ReminderRequest} child class used for creating reminders of alarm clocks.
     * You can use this class to publish alarm reminders at a specified time (accurate to minute) on a
     * particular day or on particular days every week.
     *
     * @note The params must meet the following conditions,
     * otherwise the application may crash due to an illegal parameter exception.
     *
     * @param hour The value must between [0, 23].
     * @param minute The value must between [0, 59].
     * @param daysOfWeek The value must between [1, 7], and the length of array can not be greater than 7.
     *
     * @see ReminderRequestTimer
     */
    ReminderRequestAlarm(uint8_t hour, uint8_t minute, std::vector<uint8_t> daysOfWeek);

    /**
     * @brief This constructor should only be used in background proxy service process
     * when reminder instance recovery from database.
     *
     * @param reminderId Indicates reminder id.
     */
    explicit ReminderRequestAlarm(int32_t reminderId) : ReminderRequest(reminderId)
    {
        SetReminderType(ReminderType::ALARM);
    };

    /**
     * @brief Copy construct from an exist reminder.
     *
     * @param Indicates the exist alarm reminder.
     */
    explicit ReminderRequestAlarm(const ReminderRequestAlarm &other);
    ReminderRequestAlarm& operator = (const ReminderRequestAlarm &other);
    ~ReminderRequestAlarm() override {};

    /**
     * @brief Obtains the setted {@link hour_}.
     *
     * @return setted hour.
     */
    uint8_t GetHour() const;

    /**
     * @brief Obtains the setted {@link minute_}.
     *
     * @return setted minute.
     */
    uint8_t GetMinute() const;

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

    virtual bool UpdateNextReminder() override;

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
    static ReminderRequestAlarm *Unmarshalling(Parcel &parcel);

    /**
     * Unmarshal unique properties of alarm from a Parcel.
     *
     * @param parcel Indicates the Parcel.
     * @return true if read parcel success.
     */
    bool ReadFromParcel(Parcel &parcel) override;
    bool WriteParcel(Parcel &parcel) const override;

    ReminderRequestAlarm() : ReminderRequest(ReminderType::ALARM) {};

protected:
    virtual uint64_t PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext) override;

private:
    void CheckParamValid() const;

    /**
     * Obtains the next trigger time.
     *
     * @param forceToGetNext Indicates whether force to get next reminder.
     *                       When set the alarm firstly, you should set force with true, so if repeat information
     *                       is not set, and the target time is overdue, the reminder will be set to next day.
     *                       When change the time manually by user, you should set force with false, so if repeat
     *                       information is not set, and target time is overdue, the reminder will not be set to
     *                       next day.
     * @return next trigger time in milli.
     */
    uint64_t GetNextTriggerTime(bool forceToGetNext) const;
    bool IsRepeatReminder() const;

    static const uint8_t MINUTES_PER_HOUR;
    static const int8_t DEFAULT_SNOOZE_TIMES;

    uint8_t hour_ = {0};
    uint8_t minute_ = {0};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_ALARM_H