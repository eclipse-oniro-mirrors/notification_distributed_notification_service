/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "reminder_table.h"

namespace OHOS {
namespace Notification {
// reminder base table
const std::string ReminderBaseTable::TABLE_NAME = "reminder_base";
const std::string ReminderBaseTable::REMINDER_ID = "reminder_id";
const std::string ReminderBaseTable::PACKAGE_NAME = "package_name";
const std::string ReminderBaseTable::USER_ID = "user_id";
const std::string ReminderBaseTable::UID = "uid";
const std::string ReminderBaseTable::SYSTEM_APP = "system_app";
const std::string ReminderBaseTable::REMINDER_TYPE = "reminder_type";
const std::string ReminderBaseTable::REMINDER_TIME = "reminder_time";
const std::string ReminderBaseTable::TRIGGER_TIME = "trigger_time";
const std::string ReminderBaseTable::TIME_INTERVAL = "time_interval";
const std::string ReminderBaseTable::SNOOZE_TIMES = "snooze_times";
const std::string ReminderBaseTable::DYNAMIC_SNOOZE_TIMES = "dynamic_snooze_times";
const std::string ReminderBaseTable::RING_DURATION = "ring_duration";
const std::string ReminderBaseTable::IS_EXPIRED = "is_expired";
const std::string ReminderBaseTable::STATE = "state";
const std::string ReminderBaseTable::ACTION_BUTTON_INFO = "button_info";
const std::string ReminderBaseTable::CUSTOM_BUTTON_URI = "custom_button_uri";
const std::string ReminderBaseTable::SLOT_ID = "slot_id";
const std::string ReminderBaseTable::SNOOZE_SLOT_ID = "snooze_slot_id";
const std::string ReminderBaseTable::NOTIFICATION_ID = "notification_id";
const std::string ReminderBaseTable::TITLE = "title";
const std::string ReminderBaseTable::TITLE_RESOURCE_ID = "title_resource_id";
const std::string ReminderBaseTable::CONTENT = "content";
const std::string ReminderBaseTable::CONTENT_RESOURCE_ID = "content_resource_id";
const std::string ReminderBaseTable::SNOOZE_CONTENT = "snooze_content";
const std::string ReminderBaseTable::SNOOZE_CONTENT_RESOURCE_ID = "snooze_content_resource_id";
const std::string ReminderBaseTable::EXPIRED_CONTENT = "expired_content";
const std::string ReminderBaseTable::EXPIRED_CONTENT_RESOURCE_ID = "expired_content_resource_id";
const std::string ReminderBaseTable::WANT_AGENT = "want_agent";
const std::string ReminderBaseTable::MAX_SCREEN_WANT_AGENT = "max_screen_want_agent";
const std::string ReminderBaseTable::TAP_DISMISSED = "tap_dismissed";
const std::string ReminderBaseTable::AUTO_DELETED_TIME = "auto_deleted_time";
const std::string ReminderBaseTable::GROUP_ID = "group_id";
const std::string ReminderBaseTable::CUSTOM_RING_URI = "custom_ring_uri";
const std::string ReminderBaseTable::CREATOR_BUNDLE_NAME = "creator_bundle_name";
const std::string ReminderBaseTable::CREATOR_UID = "creator_uid";

// reminder alarm table
const std::string ReminderAlarmTable::TABLE_NAME = "reminder_alarm";
const std::string ReminderAlarmTable::REMINDER_ID = "reminder_id";
const std::string ReminderAlarmTable::ALARM_HOUR = "alarm_hour";
const std::string ReminderAlarmTable::ALARM_MINUTE = "alarm_minute";
const std::string ReminderAlarmTable::REPEAT_DAYS_OF_WEEK = "repeat_days_of_week";

// reminder calendar table
const std::string ReminderCalendarTable::TABLE_NAME = "reminder_calendar";
const std::string ReminderCalendarTable::REMINDER_ID = "reminder_id";
const std::string ReminderCalendarTable::FIRST_DESIGNATE_YEAR = "first_designate_year";
const std::string ReminderCalendarTable::FIRST_DESIGNATE_MONTH = "first_designate_month";
const std::string ReminderCalendarTable::FIRST_DESIGNATE_DAY = "first_designate_day";
const std::string ReminderCalendarTable::CALENDAR_DATE_TIME = "calendar_date_time";
const std::string ReminderCalendarTable::CALENDAR_END_DATE_TIME = "calendar_end_date_time";
const std::string ReminderCalendarTable::REPEAT_DAYS = "repeat_days";
const std::string ReminderCalendarTable::REPEAT_MONTHS = "repeat_months";
const std::string ReminderCalendarTable::REPEAT_DAYS_OF_WEEK = "repeat_days_of_week";
const std::string ReminderCalendarTable::RRULE_WANT_AGENT = "rrule_want_agent";
const std::string ReminderCalendarTable::EXCLUDE_DATES = "exclude_dates";
const std::string ReminderCalendarTable::CALENDAR_LAST_DATE_TIME = "calendar_last_date_time";

// reminder timer table
const std::string ReminderTimerTable::TABLE_NAME = "reminder_timer";
const std::string ReminderTimerTable::REMINDER_ID = "reminder_id";
const std::string ReminderTimerTable::TRIGGER_SECOND = "trigger_second";
const std::string ReminderTimerTable::START_DATE_TIME = "start_date_time";
const std::string ReminderTimerTable::END_DATE_TIME = "end_date_time";

std::string ReminderBaseTable::ADD_COLUMNS = "";
std::string ReminderBaseTable::SELECT_COLUMNS = "";

std::string ReminderAlarmTable::ADD_COLUMNS = "";
std::string ReminderAlarmTable::SELECT_COLUMNS = "";

std::string ReminderCalendarTable::ADD_COLUMNS = "";
std::string ReminderCalendarTable::SELECT_COLUMNS = "";

std::string ReminderTimerTable::ADD_COLUMNS = "";
std::string ReminderTimerTable::SELECT_COLUMNS = "";

static inline void AddColumn(const std::string& name, const std::string& type, std::string& sqlOfColumns,
    std::string& columns)
{
    columns.append(name).append(",");
    sqlOfColumns.append(name).append(" ");
    sqlOfColumns.append(type).append(", ");
}

static inline void AddColumnEnd(const std::string& name, const std::string& type, std::string& sqlOfColumns,
    std::string& columns)
{
    columns.append(name);
    sqlOfColumns.append(name).append(" ");
    sqlOfColumns.append(type);
}

void ReminderBaseTable::InitDbColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(PACKAGE_NAME, "TEXT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(USER_ID, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(UID, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SYSTEM_APP, "TEXT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(REMINDER_TYPE, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(REMINDER_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TRIGGER_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TIME_INTERVAL, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SNOOZE_TIMES, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(DYNAMIC_SNOOZE_TIMES, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(RING_DURATION, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(IS_EXPIRED, "TEXT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(STATE, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(ACTION_BUTTON_INFO, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CUSTOM_BUTTON_URI, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SLOT_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SNOOZE_SLOT_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(NOTIFICATION_ID, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TITLE, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TITLE_RESOURCE_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CONTENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CONTENT_RESOURCE_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SNOOZE_CONTENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(SNOOZE_CONTENT_RESOURCE_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(EXPIRED_CONTENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(EXPIRED_CONTENT_RESOURCE_ID, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(WANT_AGENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(MAX_SCREEN_WANT_AGENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TAP_DISMISSED, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(AUTO_DELETED_TIME, "BIGINT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(GROUP_ID, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CUSTOM_RING_URI, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(RING_CHANNEL, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(FORCE_DISTRIBUTED, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(NOT_DISTRIBUTED, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CREATOR_BUNDLE_NAME, "TEXT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumnEnd(CREATOR_UID, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
}

void ReminderAlarmTable::InitDbColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(ALARM_HOUR, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(ALARM_MINUTE, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumnEnd(REPEAT_DAYS_OF_WEEK, "INT", ADD_COLUMNS, SELECT_COLUMNS);
}

void ReminderCalendarTable::InitDbColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(FIRST_DESIGNATE_YEAR, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(FIRST_DESIGNATE_MONTH, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(FIRST_DESIGNATE_DAY, "INT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CALENDAR_DATE_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(CALENDAR_END_DATE_TIME, "BIGINT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(REPEAT_DAYS, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(REPEAT_MONTHS, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(REPEAT_DAYS_OF_WEEK, "INT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(RRULE_WANT_AGENT, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(EXCLUDE_DATES, "TEXT", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumnEnd(CALENDAR_LAST_DATE_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
}

void ReminderTimerTable::InitDbColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(TRIGGER_SECOND, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumn(START_DATE_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
    AddColumnEnd(END_DATE_TIME, "BIGINT NOT NULL", ADD_COLUMNS, SELECT_COLUMNS);
}
}
}
