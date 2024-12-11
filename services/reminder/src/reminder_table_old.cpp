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

#include "reminder_table_old.h"

namespace OHOS {
namespace Notification {
// Reminder Table Basic Columns.
const std::string ReminderTable::TABLE_NAME = "reminder";
const std::string ReminderTable::REMINDER_ID = "reminder_id";
const std::string ReminderTable::PKG_NAME = "package_name";
const std::string ReminderTable::USER_ID = "user_id";
const std::string ReminderTable::UID = "uid";
const std::string ReminderTable::SYS_APP = "system_app";
const std::string ReminderTable::APP_LABEL = "app_label";
const std::string ReminderTable::REMINDER_TYPE = "reminder_type";
const std::string ReminderTable::REMINDER_TIME = "reminder_time";
const std::string ReminderTable::TRIGGER_TIME = "trigger_time";
const std::string ReminderTable::RTC_TRIGGER_TIME = "rtc_trigger_time";
const std::string ReminderTable::TIME_INTERVAL = "time_interval";
const std::string ReminderTable::SNOOZE_TIMES = "snooze_times";
const std::string ReminderTable::DYNAMIC_SNOOZE_TIMES = "dynamic_snooze_times";
const std::string ReminderTable::RING_DURATION = "ring_duration";
const std::string ReminderTable::IS_EXPIRED = "is_expired";
const std::string ReminderTable::IS_ACTIVE = "is_active";
const std::string ReminderTable::STATE = "state";
const std::string ReminderTable::ZONE_ID = "zone_id";
const std::string ReminderTable::HAS_SCHEDULED_TIMEOUT = "has_ScheduledTimeout";
const std::string ReminderTable::ACTION_BUTTON_INFO = "button_info";
const std::string ReminderTable::CUSTOM_BUTTON_URI = "custom_button_uri";
const std::string ReminderTable::SLOT_ID = "slot_id";
const std::string ReminderTable::SNOOZE_SLOT_ID = "snooze_slot_id";
const std::string ReminderTable::NOTIFICATION_ID = "notification_id";
const std::string ReminderTable::TITLE = "title";
const std::string ReminderTable::CONTENT = "content";
const std::string ReminderTable::SNOOZE_CONTENT = "snooze_content";
const std::string ReminderTable::EXPIRED_CONTENT = "expired_content";
const std::string ReminderTable::AGENT = "agent";
const std::string ReminderTable::MAX_SCREEN_AGENT = "maxScreen_agent";
const std::string ReminderTable::TAP_DISMISSED = "tapDismissed";
const std::string ReminderTable::AUTO_DELETED_TIME = "autoDeletedTime";
const std::string ReminderTable::REPEAT_DAYS_OF_WEEK = "repeat_days_of_week";
const std::string ReminderTable::GROUP_ID = "groupId";
const std::string ReminderTable::CUSTOM_RING_URI = "custom_ring_uri";
const std::string ReminderTable::CREATOR_BUNDLE_NAME = "creator_bundle_name";

// Reminder Table Calendar Columns.
const std::string ReminderTable::REPEAT_DAYS = "repeat_days";
const std::string ReminderTable::REPEAT_MONTHS = "repeat_months";
const std::string ReminderTable::FIRST_DESIGNATE_YEAR = "first_designate_year";
const std::string ReminderTable::FIRST_DESIGNATE_MONTH = "first_designate_month";
const std::string ReminderTable::FIRST_DESIGNATE_DAY = "first_designate_day";
const std::string ReminderTable::CALENDAR_YEAR = "calendar_year";
const std::string ReminderTable::CALENDAR_MONTH = "calendar_month";
const std::string ReminderTable::CALENDAR_DAY = "calendar_day";
const std::string ReminderTable::CALENDAR_HOUR = "calendar_hour";
const std::string ReminderTable::CALENDAR_MINUTE = "calendar_minute";

// Reminder Table Alarm Columns.
const std::string ReminderTable::ALARM_HOUR = "alarm_hour";
const std::string ReminderTable::ALARM_MINUTE = "alarm_minute";

std::string ReminderTable::ADD_COLUMNS = "";
std::string ReminderTable::SELECT_COLUMNS = "";

void ReminderTable::InitDbColumns()
{
    InitBasicColumns();
    InitCalendarColumns();
    InitAlarmColumns();
}

void ReminderTable::InitBasicColumns()
{
    AddColumn(REMINDER_ID, "INTEGER PRIMARY KEY");
    AddColumn(PKG_NAME, "TEXT NOT NULL");
    AddColumn(USER_ID, "INT NOT NULL");
    AddColumn(UID, "INT NOT NULL");
    AddColumn(SYS_APP, "TEXT NOT NULL");
    AddColumn(APP_LABEL, "TEXT");
    AddColumn(REMINDER_TYPE, "INT NOT NULL");
    AddColumn(REMINDER_TIME, "BIGINT NOT NULL");
    AddColumn(TRIGGER_TIME, "BIGINT NOT NULL");
    AddColumn(RTC_TRIGGER_TIME, "BIGINT NOT NULL");
    AddColumn(TIME_INTERVAL, "BIGINT NOT NULL");
    AddColumn(SNOOZE_TIMES, "INT NOT NULL");
    AddColumn(DYNAMIC_SNOOZE_TIMES, "INT NOT NULL");
    AddColumn(RING_DURATION, "BIGINT NOT NULL");
    AddColumn(IS_EXPIRED, "TEXT NOT NULL");
    AddColumn(IS_ACTIVE, "TEXT NOT NULL");
    AddColumn(STATE, "INT NOT NULL");
    AddColumn(ZONE_ID, "TEXT");
    AddColumn(HAS_SCHEDULED_TIMEOUT, "TEXT");
    AddColumn(ACTION_BUTTON_INFO, "TEXT");
    AddColumn(CUSTOM_BUTTON_URI, "TEXT");
    AddColumn(SLOT_ID, "INT");
    AddColumn(SNOOZE_SLOT_ID, "INT");
    AddColumn(NOTIFICATION_ID, "INT NOT NULL");
    AddColumn(TITLE, "TEXT");
    AddColumn(CONTENT, "TEXT");
    AddColumn(SNOOZE_CONTENT, "TEXT");
    AddColumn(EXPIRED_CONTENT, "TEXT");
    AddColumn(AGENT, "TEXT");
    AddColumn(MAX_SCREEN_AGENT, "TEXT");
    AddColumn(TAP_DISMISSED, "TEXT");
    AddColumn(AUTO_DELETED_TIME, "BIGINT");
    AddColumn(REPEAT_DAYS_OF_WEEK, "INT");
    AddColumn(GROUP_ID, "TEXT");
    AddColumn(CUSTOM_RING_URI, "TEXT");
    AddColumn(CREATOR_BUNDLE_NAME, "TEXT", false);
}

void ReminderTable::InitCalendarColumns()
{
    AddColumn(REPEAT_DAYS, "INT");
    AddColumn(REPEAT_MONTHS, "INT");
    AddColumn(FIRST_DESIGNATE_YEAR, "INT");
    AddColumn(FIRST_DESIGNATE_MONTH, "INT");
    AddColumn(FIRST_DESIGNATE_DAY, "INT");
    AddColumn(CALENDAR_YEAR, "INT");
    AddColumn(CALENDAR_MONTH, "INT");
    AddColumn(CALENDAR_DAY, "INT");
    AddColumn(CALENDAR_HOUR, "INT");
    AddColumn(CALENDAR_MINUTE, "INT");
}

void ReminderTable::InitAlarmColumns()
{
    AddColumn(ALARM_HOUR, "INT");
    AddColumn(ALARM_MINUTE, "INT", true);
}

void ReminderTable ::AddColumn(
    const std::string& name, const std::string& type, bool isEnd)
{
    if (!isEnd) {
        SELECT_COLUMNS.append(name).append(",");
        ADD_COLUMNS += name + " " + type + ", ";
    } else {
        SELECT_COLUMNS.append(name);
        ADD_COLUMNS += name + " " + type;
    }
}
}
}
