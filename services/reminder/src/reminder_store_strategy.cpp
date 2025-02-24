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

#include "reminder_store_strategy.h"

#include "ans_log_wrapper.h"
#include "reminder_store.h"
#include "reminder_table.h"
#include "reminder_table_old.h"
#include "reminder_request_alarm.h"
#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"

namespace OHOS {
namespace Notification {
void ReminderStrategy::AppendValuesBucket(const sptr<ReminderRequest>& reminder,
    NativeRdb::ValuesBucket &values, const bool oldVersion)
{
    values.PutInt(ReminderBaseTable::REMINDER_ID, reminder->GetReminderId());
    values.PutString(ReminderBaseTable::PACKAGE_NAME, reminder->GetBundleName());
    values.PutInt(ReminderBaseTable::USER_ID, reminder->GetUserId());
    values.PutInt(ReminderBaseTable::UID, reminder->GetUid());
    values.PutString(ReminderBaseTable::SYSTEM_APP, reminder->IsSystemApp() ? "true" : "false");
    values.PutInt(ReminderBaseTable::REMINDER_TYPE, static_cast<int32_t>(reminder->GetReminderType()));
    values.PutLong(ReminderBaseTable::REMINDER_TIME, reminder->GetReminderTimeInMilli());
    values.PutLong(ReminderBaseTable::TRIGGER_TIME, reminder->GetTriggerTimeInMilli());
    values.PutLong(ReminderBaseTable::TIME_INTERVAL, reminder->GetTimeInterval());
    values.PutInt(ReminderBaseTable::SNOOZE_TIMES, reminder->GetSnoozeTimes());
    values.PutInt(ReminderBaseTable::DYNAMIC_SNOOZE_TIMES, reminder->GetSnoozeTimesDynamic());
    values.PutLong(ReminderBaseTable::RING_DURATION, reminder->GetRingDuration());
    values.PutString(ReminderBaseTable::IS_EXPIRED, reminder->IsExpired() ? "true" : "false");
    values.PutInt(ReminderBaseTable::STATE, reminder->GetState());
    values.PutString(ReminderBaseTable::ACTION_BUTTON_INFO, reminder->SerializeButtonInfo());
    values.PutString(ReminderBaseTable::CUSTOM_BUTTON_URI, reminder->GetCustomButtonUri());
    values.PutInt(ReminderBaseTable::SLOT_ID, reminder->GetSlotType());
    values.PutInt(ReminderBaseTable::SNOOZE_SLOT_ID, reminder->GetSnoozeSlotType());
    values.PutInt(ReminderBaseTable::NOTIFICATION_ID, reminder->GetNotificationId());
    values.PutString(ReminderBaseTable::TITLE, reminder->GetTitle());
    values.PutInt(ReminderBaseTable::TITLE_RESOURCE_ID, reminder->GetTitleResourceId());
    values.PutString(ReminderBaseTable::CONTENT, reminder->GetContent());
    values.PutInt(ReminderBaseTable::CONTENT_RESOURCE_ID, reminder->GetContentResourceId());
    values.PutString(ReminderBaseTable::SNOOZE_CONTENT, reminder->GetSnoozeContent());
    values.PutInt(ReminderBaseTable::SNOOZE_CONTENT_RESOURCE_ID, reminder->GetSnoozeContentResourceId());
    values.PutString(ReminderBaseTable::EXPIRED_CONTENT, reminder->GetExpiredContent());
    values.PutInt(ReminderBaseTable::EXPIRED_CONTENT_RESOURCE_ID, reminder->GetExpiredContentResourceId());

    if (oldVersion) {
        values.PutString(ReminderBaseTable::WANT_AGENT, reminder->GetWantAgentStr());
        values.PutString(ReminderBaseTable::MAX_SCREEN_WANT_AGENT, reminder->GetMaxWantAgentStr());
    } else {
        std::string wantInfoStr;
        std::string maxWantInfoStr;
        reminder->SerializeWantAgent(wantInfoStr, maxWantInfoStr);
        values.PutString(ReminderBaseTable::WANT_AGENT, wantInfoStr);
        values.PutString(ReminderBaseTable::MAX_SCREEN_WANT_AGENT, maxWantInfoStr);
    }
    
    values.PutString(ReminderBaseTable::TAP_DISMISSED, reminder->IsTapDismissed() ? "true" : "false");
    values.PutLong(ReminderBaseTable::AUTO_DELETED_TIME, reminder->GetAutoDeletedTime());
    values.PutString(ReminderBaseTable::GROUP_ID, reminder->GetGroupId());
    values.PutString(ReminderBaseTable::CUSTOM_RING_URI, reminder->GetCustomRingUri());
    values.PutString(ReminderBaseTable::CREATOR_BUNDLE_NAME, reminder->GetCreatorBundleName());
    values.PutInt(ReminderBaseTable::CREATOR_UID, reminder->GetCreatorUid());
}

void ReminderStrategy::RecoverTimeFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    uint64_t reminderTime = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderTable::REMINDER_TIME, reminderTime);
    reminder->SetReminderTimeInMilli(reminderTime);

    uint64_t triggerTime = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderTable::TRIGGER_TIME, triggerTime);
    reminder->SetTriggerTimeInMilli(triggerTime);

    uint64_t timeInterval = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderTable::TIME_INTERVAL, timeInterval);
    reminder->SetTimeInterval(timeInterval);

    uint8_t snoozeTimes = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::SNOOZE_TIMES, snoozeTimes);
    reminder->SetSnoozeTimes(snoozeTimes);

    uint8_t dynamicSnoozeTimes = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::DYNAMIC_SNOOZE_TIMES, dynamicSnoozeTimes);
    reminder->SetSnoozeTimesDynamic(dynamicSnoozeTimes);

    uint64_t ringDuration = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderTable::RING_DURATION, ringDuration);
    reminder->SetRingDuration(ringDuration);

    int64_t autoDeletedTime = 0;
    ReminderStrategy::GetRdbValue<int64_t>(resultSet, ReminderTable::AUTO_DELETED_TIME, autoDeletedTime);
    reminder->SetAutoDeletedTime(autoDeletedTime);
}

void ReminderStrategy::RecoverIdFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    int32_t reminderId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::REMINDER_ID, reminderId);
    reminder->SetReminderId(reminderId);

    int32_t userId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::USER_ID, userId);
    reminder->InitUserId(userId);

    int32_t uid = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::UID, uid);
    reminder->InitUid(uid);

    int32_t reminderType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::REMINDER_TYPE, reminderType);
    reminder->SetReminderType(ReminderRequest::ReminderType(reminderType));

    int32_t slotType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::SLOT_ID, slotType);
    reminder->SetSlotType(NotificationConstant::SlotType(slotType));

    int32_t snoozeSlotType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::SNOOZE_SLOT_ID, snoozeSlotType);
    reminder->SetSnoozeSlotType(NotificationConstant::SlotType(snoozeSlotType));

    int32_t notificationId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderTable::NOTIFICATION_ID, notificationId);
    reminder->SetNotificationId(notificationId);

    std::string groupId;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::GROUP_ID, groupId);
    reminder->SetGroupId(groupId);
}

void ReminderStrategy::RecoverContextFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    std::string bundleName;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::PKG_NAME, bundleName);
    reminder->InitBundleName(bundleName);

    std::string title;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::TITLE, title);
    reminder->SetTitle(title);

    std::string content;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::CONTENT, content);
    reminder->SetContent(content);

    std::string snoozeContent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::SNOOZE_CONTENT, snoozeContent);
    reminder->SetSnoozeContent(snoozeContent);

    std::string expiredContent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::EXPIRED_CONTENT, expiredContent);
    reminder->SetExpiredContent(expiredContent);

    std::string customButtonUri;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::CUSTOM_BUTTON_URI, customButtonUri);
    reminder->SetCustomButtonUri(customButtonUri);

    std::string customRingUri;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::CUSTOM_RING_URI, customRingUri);
    reminder->SetCustomRingUri(customRingUri);

    std::string creatorBundleName;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::CREATOR_BUNDLE_NAME, creatorBundleName);
    reminder->InitCreatorBundleName(creatorBundleName);
}

void ReminderStrategy::RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (reminder == nullptr || resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }

    ReminderStrategy::RecoverTimeFromOldVersion(reminder, resultSet);
    ReminderStrategy::RecoverIdFromOldVersion(reminder, resultSet);
    ReminderStrategy::RecoverContextFromOldVersion(reminder, resultSet);

    std::string isSystemApp;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::SYS_APP, isSystemApp);
    reminder->SetSystemApp(isSystemApp == "true" ? true : false);

    std::string isExpired;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::IS_EXPIRED, isExpired);
    reminder->SetExpired(isExpired == "true" ? true : false);

    std::string actionButtons;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::ACTION_BUTTON_INFO, actionButtons);
    reminder->DeserializeButtonInfo(actionButtons);

    uint8_t state = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::STATE, state);
    reminder->SetState(state);

    uint8_t repeatDaysOfWeek = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
    reminder->SetRepeatDaysOfWeek(repeatDaysOfWeek);

    std::string wantAgent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::AGENT, wantAgent);
    reminder->SetWantAgentStr(wantAgent);

    std::string maxScreenWantAgent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::MAX_SCREEN_AGENT, maxScreenWantAgent);
    reminder->SetMaxWantAgentStr(maxScreenWantAgent);

    std::string tapDismissed;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderTable::TAP_DISMISSED, tapDismissed);
    reminder->SetTapDismissed(tapDismissed == "true" ? true : false);
}

void ReminderStrategy::RecoverTimeFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    uint64_t reminderTime = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderBaseTable::REMINDER_TIME, reminderTime);
    reminder->SetReminderTimeInMilli(reminderTime);

    uint64_t triggerTime = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderBaseTable::TRIGGER_TIME, triggerTime);
    reminder->SetTriggerTimeInMilli(triggerTime);

    uint64_t timeInterval = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderBaseTable::TIME_INTERVAL, timeInterval);
    reminder->SetTimeInterval(timeInterval);

    uint8_t snoozeTimes = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderBaseTable::SNOOZE_TIMES, snoozeTimes);
    reminder->SetSnoozeTimes(snoozeTimes);

    uint8_t dynamicSnoozeTimes = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderBaseTable::DYNAMIC_SNOOZE_TIMES, dynamicSnoozeTimes);
    reminder->SetSnoozeTimesDynamic(dynamicSnoozeTimes);

    uint64_t ringDuration = 0;
    ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderBaseTable::RING_DURATION, ringDuration);
    reminder->SetRingDuration(ringDuration);

    int64_t autoDeletedTime = 0;
    ReminderStrategy::GetRdbValue<int64_t>(resultSet, ReminderBaseTable::AUTO_DELETED_TIME, autoDeletedTime);
    reminder->SetAutoDeletedTime(autoDeletedTime);
}

void ReminderStrategy::RecoverIdFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    int32_t reminderId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::REMINDER_ID, reminderId);
    reminder->SetReminderId(reminderId);

    int32_t userId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::USER_ID, userId);
    reminder->InitUserId(userId);

    int32_t uid = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::UID, uid);
    reminder->InitUid(uid);

    int32_t reminderType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::REMINDER_TYPE, reminderType);
    reminder->SetReminderType(ReminderRequest::ReminderType(reminderType));

    int32_t slotType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::SLOT_ID, slotType);
    reminder->SetSlotType(NotificationConstant::SlotType(slotType));

    int32_t snoozeSlotType = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::SNOOZE_SLOT_ID, snoozeSlotType);
    reminder->SetSnoozeSlotType(NotificationConstant::SlotType(snoozeSlotType));

    int32_t notificationId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::NOTIFICATION_ID, notificationId);
    reminder->SetNotificationId(notificationId);

    std::string groupId;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::GROUP_ID, groupId);
    reminder->SetGroupId(groupId);

    int32_t creatorUid;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::CREATOR_UID, creatorUid);
    reminder->InitCreatorUid(creatorUid);

    int32_t titleResourceId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::TITLE_RESOURCE_ID, titleResourceId);
    reminder->SetTitleResourceId(titleResourceId);

    int32_t contentResourceId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::CONTENT_RESOURCE_ID, contentResourceId);
    reminder->SetContentResourceId(contentResourceId);

    int32_t snoozeContentResourceId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::SNOOZE_CONTENT_RESOURCE_ID,
        snoozeContentResourceId);
    reminder->SetSnoozeContentResourceId(snoozeContentResourceId);

    int32_t expiredContentResourceId = 0;
    ReminderStrategy::GetRdbValue<int32_t>(resultSet, ReminderBaseTable::EXPIRED_CONTENT_RESOURCE_ID,
        expiredContentResourceId);
    reminder->SetExpiredContentResourceId(expiredContentResourceId);
}

void ReminderStrategy::RecoverContextFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    std::string bundleName;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::PACKAGE_NAME, bundleName);
    reminder->InitBundleName(bundleName);

    std::string customButtonUri;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::CUSTOM_BUTTON_URI, customButtonUri);
    reminder->SetCustomButtonUri(customButtonUri);

    std::string title;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::TITLE, title);
    reminder->SetTitle(title);

    std::string content;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::CONTENT, content);
    reminder->SetContent(content);

    std::string snoozeContent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::SNOOZE_CONTENT, snoozeContent);
    reminder->SetSnoozeContent(snoozeContent);

    std::string expiredContent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::EXPIRED_CONTENT, expiredContent);
    reminder->SetExpiredContent(expiredContent);

    std::string customRingUri;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::CUSTOM_RING_URI, customRingUri);
    reminder->SetCustomRingUri(customRingUri);

    std::string creatorBundleName;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::CREATOR_BUNDLE_NAME, creatorBundleName);
    reminder->InitCreatorBundleName(creatorBundleName);
}

void ReminderStrategy::RecoverFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (reminder == nullptr || resultSet == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverTimeFromDb(reminder, resultSet);
    ReminderStrategy::RecoverIdFromDb(reminder, resultSet);
    ReminderStrategy::RecoverContextFromDb(reminder, resultSet);

    uint8_t state = 0;
    ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderBaseTable::STATE, state);
    reminder->SetState(state);

    std::string isSystemApp;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::SYSTEM_APP, isSystemApp);
    reminder->SetSystemApp(isSystemApp == "true" ? true : false);

    std::string isExpired;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::IS_EXPIRED, isExpired);
    reminder->SetExpired(isExpired == "true" ? true : false);

    std::string actionButtons;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::ACTION_BUTTON_INFO, actionButtons);
    reminder->DeserializeButtonInfo(actionButtons);

    std::string wantAgent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::WANT_AGENT, wantAgent);
    reminder->DeserializeWantAgent(wantAgent, 0);

    std::string maxWantAgent;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::MAX_SCREEN_WANT_AGENT, maxWantAgent);
    reminder->DeserializeWantAgent(maxWantAgent, 1);

    std::string tapDismissed;
    ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderBaseTable::TAP_DISMISSED, tapDismissed);
    reminder->SetTapDismissed(tapDismissed == "true" ? true : false);
}

void ReminderTimerStrategy::AppendValuesBucket(const sptr<ReminderRequest>& reminder,
    NativeRdb::ValuesBucket& values)
{
    uint64_t seconds = 0;
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::TIMER) {
        ReminderRequestTimer* timer = static_cast<ReminderRequestTimer*>(reminder.GetRefPtr());
        seconds = timer->GetInitInfo();
    }
    values.PutInt(ReminderTimerTable::REMINDER_ID, reminder->GetReminderId());
    values.PutLong(ReminderTimerTable::TRIGGER_SECOND, seconds);
    values.PutLong(ReminderTimerTable::START_DATE_TIME, 0);
    values.PutLong(ReminderTimerTable::END_DATE_TIME, 0);
}

void ReminderTimerStrategy::RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromOldVersion(reminder, resultSet);
}

void ReminderTimerStrategy::RecoverFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& baseResult, const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr || baseResult == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromDb(reminder, baseResult);
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::TIMER) {
        ReminderRequestTimer* timer = static_cast<ReminderRequestTimer*>(reminder.GetRefPtr());
        uint64_t seconds;
        ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderTimerTable::TRIGGER_SECOND, seconds);
        timer->SetInitInfo(seconds);
    }
}

void ReminderAlarmStrategy::AppendValuesBucket(const sptr<ReminderRequest>& reminder,
    NativeRdb::ValuesBucket& values)
{
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t repeatDaysOfWeek = 0;
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::ALARM) {
        ReminderRequestAlarm* alarm = static_cast<ReminderRequestAlarm*>(reminder.GetRefPtr());
        hour = alarm->GetHour();
        minute = alarm->GetMinute();
        repeatDaysOfWeek = alarm->GetRepeatDaysOfWeek();
    }
    values.PutInt(ReminderAlarmTable::REMINDER_ID, reminder->GetReminderId());
    values.PutInt(ReminderAlarmTable::ALARM_HOUR, hour);
    values.PutInt(ReminderAlarmTable::ALARM_MINUTE, minute);
    values.PutInt(ReminderAlarmTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
}

void ReminderAlarmStrategy::RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromOldVersion(reminder, resultSet);

    if (reminder->GetReminderType() == ReminderRequest::ReminderType::ALARM) {
        ReminderRequestAlarm* alarm = static_cast<ReminderRequestAlarm*>(reminder.GetRefPtr());
        uint8_t hour = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::ALARM_HOUR, hour);
        alarm->SetHour(hour);

        uint8_t minute = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::ALARM_MINUTE, minute);
        alarm->SetMinute(minute);
    }
}

void ReminderAlarmStrategy::RecoverFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& baseResult, const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr || baseResult == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromDb(reminder, baseResult);
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::ALARM) {
        ReminderRequestAlarm* alarm = static_cast<ReminderRequestAlarm*>(reminder.GetRefPtr());
        uint8_t hour = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderAlarmTable::ALARM_HOUR, hour);
        alarm->SetHour(hour);

        uint8_t minute = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderAlarmTable::ALARM_MINUTE, minute);
        alarm->SetMinute(minute);

        uint8_t repeatDaysOfWeek = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderAlarmTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
        alarm->SetRepeatDaysOfWeek(repeatDaysOfWeek);
    }
}

void ReminderCalendarStrategy::AppendValuesBucket(const sptr<ReminderRequest>& reminder,
    NativeRdb::ValuesBucket& values)
{
    uint16_t firstDesignateYear = 0;
    uint8_t firstDesignateMonth = 0;
    uint8_t firstDesignateDay = 0;
    uint64_t dateTime = 0;
    uint32_t repeatDay = 0;
    uint16_t repeatMonth = 0;
    uint8_t repeatDaysOfWeek = 0;
    uint64_t endDateTime = 0;
    uint64_t lastStartDateTime = 0;
    std::string rruleWantAgent;
    std::string excludeDates;
    if (reminder != nullptr && reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        if (calendar != nullptr) {
            repeatDay = calendar->GetRepeatDay();
            repeatMonth = calendar->GetRepeatMonth();
            firstDesignateYear = calendar->GetFirstDesignateYear();
            firstDesignateMonth = calendar->GetFirstDesignageMonth();
            firstDesignateDay = calendar->GetFirstDesignateDay();
            dateTime = calendar->GetDateTime();
            repeatDaysOfWeek = calendar->GetRepeatDaysOfWeek();
            endDateTime = calendar->GetEndDateTime();
            lastStartDateTime = calendar->GetLastStartDateTime();
            rruleWantAgent = calendar->SerializationRRule();
            excludeDates = calendar->SerializationExcludeDates();
        }
    }
    values.PutInt(ReminderCalendarTable::REMINDER_ID, reminder->GetReminderId());
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_YEAR, firstDesignateYear);
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_MONTH, firstDesignateMonth);
    values.PutInt(ReminderCalendarTable::FIRST_DESIGNATE_DAY, firstDesignateDay);
    values.PutLong(ReminderCalendarTable::CALENDAR_DATE_TIME, dateTime);
    values.PutLong(ReminderCalendarTable::CALENDAR_END_DATE_TIME, endDateTime);
    values.PutLong(ReminderCalendarTable::CALENDAR_LAST_DATE_TIME, lastStartDateTime);
    values.PutInt(ReminderCalendarTable::REPEAT_DAYS, repeatDay);
    values.PutInt(ReminderCalendarTable::REPEAT_MONTHS, repeatMonth);
    values.PutInt(ReminderCalendarTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
    values.PutString(ReminderCalendarTable::RRULE_WANT_AGENT, rruleWantAgent);
    values.PutString(ReminderCalendarTable::EXCLUDE_DATES, excludeDates);
}

void ReminderCalendarStrategy::RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromOldVersion(reminder, resultSet);
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        uint32_t repeatDay = 0;
        ReminderStrategy::GetRdbValue<uint32_t>(resultSet, ReminderTable::REPEAT_DAYS, repeatDay);
        calendar->SetRepeatDay(repeatDay);

        uint16_t repeatMonth = 0;
        ReminderStrategy::GetRdbValue<uint16_t>(resultSet, ReminderTable::REPEAT_MONTHS, repeatMonth);
        calendar->SetRepeatMonth(repeatMonth);

        uint16_t firstDesignateYear = 0;
        ReminderStrategy::GetRdbValue<uint16_t>(resultSet, ReminderTable::FIRST_DESIGNATE_YEAR, firstDesignateYear);
        calendar->SetFirstDesignateYear(firstDesignateYear);

        uint8_t firstDesignateMonth = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::FIRST_DESIGNATE_MONTH, firstDesignateMonth);
        calendar->SetFirstDesignageMonth(firstDesignateMonth);

        uint8_t firstDesignateDay = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::FIRST_DESIGNATE_DAY, firstDesignateDay);
        calendar->SetFirstDesignateDay(firstDesignateDay);

        uint16_t year = 0;
        ReminderStrategy::GetRdbValue<uint16_t>(resultSet, ReminderTable::CALENDAR_YEAR, year);
        calendar->SetYear(year);

        uint8_t month = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::CALENDAR_MONTH, month);
        calendar->SetMonth(month);

        uint8_t day = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::CALENDAR_DAY, day);
        calendar->SetDay(day);

        uint8_t hour = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::CALENDAR_HOUR, hour);
        calendar->SetHour(hour);

        uint8_t minute = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderTable::CALENDAR_MINUTE, minute);
        calendar->SetMinute(minute);
    }
}

void ReminderCalendarStrategy::RecoverTime(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());

        uint16_t firstDesignateYear = 0;
        ReminderStrategy::GetRdbValue<uint16_t>(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_YEAR,
            firstDesignateYear);
        calendar->SetFirstDesignateYear(firstDesignateYear);

        uint8_t firstDesignateMonth = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_MONTH,
            firstDesignateMonth);
        calendar->SetFirstDesignageMonth(firstDesignateMonth);

        uint8_t firstDesignateDay = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderCalendarTable::FIRST_DESIGNATE_DAY,
            firstDesignateDay);
        calendar->SetFirstDesignateDay(firstDesignateDay);

        uint64_t dateTime = 0;
        ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderCalendarTable::CALENDAR_DATE_TIME, dateTime);
        calendar->SetDateTime(dateTime);

        uint64_t endDateTime = 0;
        ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderCalendarTable::CALENDAR_END_DATE_TIME, endDateTime);
        if (endDateTime != 0 && endDateTime >= dateTime) {
            calendar->SetEndDateTime(endDateTime);
        } else {
            calendar->SetEndDateTime(dateTime);
        }

        uint64_t lastStartDateTime = 0;
        ReminderStrategy::GetRdbValue<uint64_t>(resultSet, ReminderCalendarTable::CALENDAR_LAST_DATE_TIME,
            lastStartDateTime);
        if (lastStartDateTime == 0) {
            calendar->SetLastStartDateTime(dateTime);
        } else {
            calendar->SetLastStartDateTime(lastStartDateTime);
        }
    }
}

void ReminderCalendarStrategy::RecoverFromDb(sptr<ReminderRequest>& reminder,
    const std::shared_ptr<NativeRdb::ResultSet>& baseResult, const std::shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    if (resultSet == nullptr || reminder == nullptr || baseResult == nullptr) {
        ANSR_LOGE("ResultSet is null or reminder is null");
        return;
    }
    ReminderStrategy::RecoverFromDb(reminder, baseResult);
    ReminderCalendarStrategy::RecoverTime(reminder, resultSet);
    if (reminder != nullptr && reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());

        uint32_t repeatDay = 0;
        ReminderStrategy::GetRdbValue<uint32_t>(resultSet, ReminderCalendarTable::REPEAT_DAYS, repeatDay);
        calendar->SetRepeatDay(repeatDay);

        uint16_t repeatMonth = 0;
        ReminderStrategy::GetRdbValue<uint16_t>(resultSet, ReminderCalendarTable::REPEAT_MONTHS, repeatMonth);
        calendar->SetRepeatMonth(repeatMonth);

        uint8_t repeatDaysOfWeek = 0;
        ReminderStrategy::GetRdbValue<uint8_t>(resultSet, ReminderCalendarTable::REPEAT_DAYS_OF_WEEK, repeatDaysOfWeek);
        calendar->SetRepeatDaysOfWeek(repeatDaysOfWeek);

        std::string rruleWantAgent;
        ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderCalendarTable::RRULE_WANT_AGENT, rruleWantAgent);
        calendar->DeserializationRRule(rruleWantAgent);

        std::string excludeDates;
        ReminderStrategy::GetRdbValue<std::string>(resultSet, ReminderCalendarTable::EXCLUDE_DATES, excludeDates);
        calendar->DeserializationExcludeDates(excludeDates);
    }
}
}
}