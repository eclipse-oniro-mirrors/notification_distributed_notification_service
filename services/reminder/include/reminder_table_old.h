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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_OLD_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_OLD_H

#include <vector>
#include <string>

namespace OHOS {
namespace Notification {
class ReminderTable {
public:
    static void InitDbColumns();

    static const std::string TABLE_NAME;

    // Reminder Table Basic Columns.

    /*
     * reminder id
     */
    static const std::string REMINDER_ID;

    /*
     * package name
     */
    static const std::string PKG_NAME;

    /*
     * user id
     */
    static const std::string USER_ID;

    /*
     * uid
     */
    static const std::string UID;

    /*
     * systerm app flag
     */
    static const std::string SYS_APP;

    /*
     * app label
     */
    static const std::string APP_LABEL;

    /*
     * reminder type: Timer/Calendar/Alarm
     */
    static const std::string REMINDER_TYPE;

    /*
     * reminder time
     */
    static const std::string REMINDER_TIME;

    /*
     * trigger time
     */
    static const std::string TRIGGER_TIME;

    /*
     * RTC trigger time
     */
    static const std::string RTC_TRIGGER_TIME;

    /*
     * time interval
     */
    static const std::string TIME_INTERVAL;

    /*
     * snooze times
     */
    static const std::string SNOOZE_TIMES;

    /*
     * dynamic snooze times
     */
    static const std::string DYNAMIC_SNOOZE_TIMES;

    /*
     * ring duration
     */
    static const std::string RING_DURATION;

    /*
     * expired flag
     */
    static const std::string IS_EXPIRED;

    /*
     * active flag
     */
    static const std::string IS_ACTIVE;

    /*
     * reminder state
     */
    static const std::string STATE;

    /*
     * zone id
     */
    static const std::string ZONE_ID;

    /*
     * scheduled timeout flag
     */
    static const std::string HAS_SCHEDULED_TIMEOUT;

    /*
     * action button information
     */
    static const std::string ACTION_BUTTON_INFO;

    /*
     * custom button uri
     */
    static const std::string CUSTOM_BUTTON_URI;

    /*
     * slot type
     */
    static const std::string SLOT_ID;

    /*
     * snoozeslot type
     */
    static const std::string SNOOZE_SLOT_ID;

    /*
     * notification id
     */
    static const std::string NOTIFICATION_ID;

    /*
     * notification title
     */
    static const std::string TITLE;

    /*
     * notification content
     */
    static const std::string CONTENT;

    /*
     * notification snooze content
     */
    static const std::string SNOOZE_CONTENT;

    /*
     * notification expired content
     */
    static const std::string EXPIRED_CONTENT;

    /*
     * agent information
     */
    static const std::string AGENT;

    /*
     * max screen agent information
     */
    static const std::string MAX_SCREEN_AGENT;

    /*
     * tap dismissed flag
     */
    static const std::string TAP_DISMISSED;

    /*
     * auto deleted time
     */
    static const std::string AUTO_DELETED_TIME;

    /*
     * repeat days of week
     */
    static const std::string REPEAT_DAYS_OF_WEEK;

    /*
     * reminder group id
     */
    static const std::string GROUP_ID;

    /*
     * reminder ring uri
     */
    static const std::string CUSTOM_RING_URI;

    /*
     * reminder creator bundle name
     */
    static const std::string CREATOR_BUNDLE_NAME;

    // Reminder Table Calendar Columns.
    static const std::string REPEAT_DAYS;
    static const std::string REPEAT_MONTHS;
    static const std::string FIRST_DESIGNATE_YEAR;
    static const std::string FIRST_DESIGNATE_MONTH;
    static const std::string FIRST_DESIGNATE_DAY;
    static const std::string CALENDAR_YEAR;
    static const std::string CALENDAR_MONTH;
    static const std::string CALENDAR_DAY;
    static const std::string CALENDAR_HOUR;
    static const std::string CALENDAR_MINUTE;

    // Reminder Table Alarm Columns.
    static const std::string ALARM_HOUR;
    static const std::string ALARM_MINUTE;

    static std::string ADD_COLUMNS;
    static std::string SELECT_COLUMNS;

private:
    static void InitBasicColumns();
    static void InitCalendarColumns();
    static void InitAlarmColumns();
    static void AddColumn(const std::string& name, const std::string& type, bool isEnd = false);
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_OLD_H
