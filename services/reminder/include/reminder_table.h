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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_H

#include <vector>
#include <string>

namespace OHOS {
namespace Notification {
class ReminderBaseTable {
public:
    /*
     * reminder base table name
     */
    static const std::string TABLE_NAME;

    /*
     * reminder id
     */
    static const std::string REMINDER_ID;

    /*
     * package name
     */
    static const std::string PACKAGE_NAME;

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
    static const std::string SYSTEM_APP;

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
     * reminder state
     */
    static const std::string STATE;

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
    static const std::string TITLE_RESOURCE_ID;

    /*
     * notification content
     */
    static const std::string CONTENT;
    static const std::string CONTENT_RESOURCE_ID;

    /*
     * notification snooze content
     */
    static const std::string SNOOZE_CONTENT;
    static const std::string SNOOZE_CONTENT_RESOURCE_ID;

    /*
     * notification expired content
     */
    static const std::string EXPIRED_CONTENT;
    static const std::string EXPIRED_CONTENT_RESOURCE_ID;

    /*
     * want agent information
     */
    static const std::string WANT_AGENT;

    /*
     * max screen want agent information
     */
    static const std::string MAX_SCREEN_WANT_AGENT;

    /*
     * tap dismissed flag
     */
    static const std::string TAP_DISMISSED;

    /*
     * auto deleted time
     */
    static const std::string AUTO_DELETED_TIME;

    /*
     * group id
     */
    static const std::string GROUP_ID;

    /*
     * custom ring uri
     */
    static const std::string CUSTOM_RING_URI;

    /*
     * creator bundle name
     */
    static const std::string CREATOR_BUNDLE_NAME;

    /*
     * creator uid
     */
    static const std::string CREATOR_UID;
    static constexpr const char* RING_CHANNEL = "ring_channel";
    static constexpr const char* FORCE_DISTRIBUTED = "force_distributed";
    static constexpr const char* NOT_DISTRIBUTED = "not_distributed";

public:
    static void InitDbColumns();

public:
    static std::string ADD_COLUMNS;
    static std::string SELECT_COLUMNS;
};

class ReminderAlarmTable {
public:
    /*
     * reminder alarm table name
     */
    static const std::string TABLE_NAME;

    /*
     * reminder timer table field
     */
    static const std::string REMINDER_ID;
    static const std::string ALARM_HOUR;
    static const std::string ALARM_MINUTE;
    static const std::string REPEAT_DAYS_OF_WEEK;

public:
    static void InitDbColumns();

public:
    static std::string ADD_COLUMNS;
    static std::string SELECT_COLUMNS;
};

class ReminderCalendarTable {
public:
    /*
     * reminder calendar table name
     */
    static const std::string TABLE_NAME;

    /*
     * reminder calendar table field
     */
    static const std::string REMINDER_ID;
    static const std::string FIRST_DESIGNATE_YEAR;
    static const std::string FIRST_DESIGNATE_MONTH;
    static const std::string FIRST_DESIGNATE_DAY;
    static const std::string CALENDAR_DATE_TIME;
    static const std::string CALENDAR_END_DATE_TIME;
    static const std::string REPEAT_DAYS;
    static const std::string REPEAT_MONTHS;
    static const std::string REPEAT_DAYS_OF_WEEK;
    static const std::string RRULE_WANT_AGENT;
    static const std::string EXCLUDE_DATES;
    static const std::string CALENDAR_LAST_DATE_TIME;

public:
    static void InitDbColumns();

public:
    static std::string ADD_COLUMNS;
    static std::string SELECT_COLUMNS;
};

class ReminderTimerTable {
public:
    /*
     * reminder timer table name
     */
    static const std::string TABLE_NAME;

    /*
     * reminder timer table field
     */
    static const std::string REMINDER_ID;
    static const std::string TRIGGER_SECOND;
    static const std::string START_DATE_TIME;
    static const std::string END_DATE_TIME;

public:
    static void InitDbColumns();

public:
    static std::string ADD_COLUMNS;
    static std::string SELECT_COLUMNS;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_TABLE_H
