/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "reminder_ani_common.h"

#include "reminder_request_alarm.h"
#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"

#include "securec.h"
#include "int_wrapper.h"
#include "tokenid_kit.h"
#include "bool_wrapper.h"
#include "ipc_skeleton.h"
#include "double_wrapper.h"
#include "string_wrapper.h"
#include "taihe/runtime.hpp"

using namespace ohos;

namespace OHOS::ReminderAgentManagerNapi {
static constexpr int32_t MAX_HOUR = 23;
static constexpr int32_t MAX_MINUTE = 59;
static constexpr uint8_t MAX_DAYS_OF_WEEK = 7;

// need to be same as WantParams
enum {
    VALUE_TYPE_NULL = -1,
    VALUE_TYPE_BOOLEAN = 1,
    VALUE_TYPE_INT = 5,
    VALUE_TYPE_DOUBLE = 8,
    VALUE_TYPE_STRING = 9,
};

template<typename T>
static std::vector<double> ConvertInt(const std::vector<T>& values)
{
    std::vector<double> results;
    results.reserve(values.size());
    for (const auto value : values) {
        results.push_back(static_cast<double>(value));
    }
    return results;
}

static bool IsValidateString(const std::string& str)
{
    if (str.find(Notification::ReminderRequest::SEP_BUTTON_VALUE_TYPE) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE_TYPE");
        return false;
    }
    if (str.find(Notification::ReminderRequest::SEP_BUTTON_VALUE) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE");
        return false;
    }
    if (str.find(Notification::ReminderRequest::SEP_BUTTON_VALUE_BLOB) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE_BLOB");
        return false;
    }
    return true;
}

std::string Common::getErrCodeMsg(const int32_t errorCode)
{
    switch (errorCode) {
        case ERR_REMINDER_PERMISSION_DENIED:
            return "Permission denied.";
        case ERR_REMINDER_INVALID_PARAM:
            return "Parameter error.";
        case ERR_REMINDER_NOTIFICATION_NOT_ENABLE:
            return "Notification not enable.";
        case ERR_REMINDER_NUMBER_OVERLOAD:
            return "The number of reminders exceeds the limit.";
        case ERR_REMINDER_NOT_EXIST:
            return "The reminder not exist.";
        case ERR_REMINDER_PACKAGE_NOT_EXIST:
            return "The package name not exist.";
        case ERR_REMINDER_CALLER_TOKEN_INVALID:
            return "The caller token invalid.";
        case ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED:
            return "The data share permission denied.";
        default:
            return "Inner error";
    }
}

bool Common::CreateReminder(const reminderAgentManager::manager::ParamReminder& reminderReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    switch (reminderReq.get_tag()) {
        case reminderAgentManager::manager::ParamReminder::tag_t::timer: {
            auto& timer = reminderReq.get_timer_ref();
            return CreateReminderTimer(timer, reminder);
        }
        case reminderAgentManager::manager::ParamReminder::tag_t::alarm: {
            auto& alarm = reminderReq.get_alarm_ref();
            return CreateReminderAlarm(alarm, reminder);
        }
        case reminderAgentManager::manager::ParamReminder::tag_t::calendar: {
            auto& calendar = reminderReq.get_calendar_ref();
            return CreateReminderCalendar(calendar, reminder);
        }
        default:
            ANSR_LOGE("Invalid reminder type.");
            return false;
    }
}

::taihe::optional<reminderAgentManager::manager::ParamReminder> Common::GenAniReminder(
    const sptr<Notification::ReminderRequest>& reminder)
{
    switch (reminder->GetReminderType()) {
        case Notification::ReminderRequest::ReminderType::TIMER: {
            reminderAgentManager::manager::ReminderRequestTimer timer {
                .base = {
                    reminderAgentManager::manager::ReminderType::key_t::REMINDER_TYPE_TIMER
                }
            };
            GenAniReminderTimer(reminder, timer);
            return ::taihe::optional<reminderAgentManager::manager::ParamReminder>::make(
                reminderAgentManager::manager::ParamReminder::make<
                reminderAgentManager::manager::ParamReminder::tag_t::timer>(timer));
        }
        case Notification::ReminderRequest::ReminderType::ALARM: {
            reminderAgentManager::manager::ReminderRequestAlarm alarm {
                .base = {
                    reminderAgentManager::manager::ReminderType::key_t::REMINDER_TYPE_ALARM
                }
            };
            GenAniReminderAlarm(reminder, alarm);
            return ::taihe::optional<reminderAgentManager::manager::ParamReminder>::make(
                reminderAgentManager::manager::ParamReminder::make<
                reminderAgentManager::manager::ParamReminder::tag_t::alarm>(alarm));
        }
        case Notification::ReminderRequest::ReminderType::CALENDAR: {
            reminderAgentManager::manager::ReminderRequestCalendar calendar {
                .base = {
                    reminderAgentManager::manager::ReminderType::key_t::REMINDER_TYPE_CALENDAR
                }
            };
            GenAniReminderCalendar(reminder, calendar);
            return ::taihe::optional<reminderAgentManager::manager::ParamReminder>::make(
                reminderAgentManager::manager::ParamReminder::make<
                reminderAgentManager::manager::ParamReminder::tag_t::calendar>(calendar));
        }
        case Notification::ReminderRequest::ReminderType::INVALID:
        default: {
            ANSR_LOGE("Invalid reminder type.");
            return ::taihe::optional<reminderAgentManager::manager::ParamReminder>();
        }
    }
}

void Common::ConvertSlotType(AniSlotType aniSlotType, Notification::NotificationConstant::SlotType& slotType)
{
    switch (aniSlotType) {
        case AniSlotType::SOCIAL_COMMUNICATION:
            slotType = Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
            break;
        case AniSlotType::SERVICE_INFORMATION:
            slotType = Notification::NotificationConstant::SlotType::SERVICE_REMINDER;
            break;
        case AniSlotType::CONTENT_INFORMATION:
            slotType = Notification::NotificationConstant::SlotType::CONTENT_INFORMATION;
            break;
        case AniSlotType::LIVE_VIEW:
            slotType = Notification::NotificationConstant::SlotType::LIVE_VIEW;
            break;
        case AniSlotType::CUSTOMER_SERVICE:
            slotType = Notification::NotificationConstant::SlotType::CUSTOMER_SERVICE;
            break;
        case AniSlotType::EMERGENCY_INFORMATION:
            slotType = Notification::NotificationConstant::SlotType::EMERGENCY_INFORMATION;
            break;
        case AniSlotType::UNKNOWN_TYPE:
        case AniSlotType::OTHER_TYPES:
        default:
            slotType = Notification::NotificationConstant::SlotType::OTHER;
            break;
    }
}

bool Common::UnWarpSlotType(uintptr_t slotType, Notification::NotificationConstant::SlotType& outSlot)
{
    ani_enum_item value = reinterpret_cast<ani_enum_item>(slotType);
    ani_env* env = ::taihe::get_env();
    if (env == nullptr || value == nullptr) {
        ANSR_LOGE("Invalid env or slotType.");
        return false;
    }
    ani_int intValue;
    if (ANI_OK != env->EnumItem_GetValue_Int(value, &intValue)) {
        ANSR_LOGE("EnumItem_GetValue_Int failed.");
        return false;
    }
    ConvertSlotType(static_cast<AniSlotType>(intValue), outSlot);
    return true;
}

bool Common::ParseIntArray(const ::taihe::array<double>& values, std::vector<uint8_t>& result, uint8_t maxLen)
{
    size_t size = values.size();
    if (size > maxLen) {
        ANSR_LOGE("The max length of array is %{pulbic}hhu", maxLen);
        return false;
    }
    for (size_t i = 0; i < size; ++i) {
        int32_t value = static_cast<int32_t>(values[i]);
        if (value < 1 || value > static_cast<int32_t>(maxLen)) {
            ANSR_LOGE("The array element must between [1, %{public}d].", maxLen);
            return false;
        }
        result.push_back(static_cast<uint8_t>(value));
    }
    return true;
}

bool Common::ParseIntParam(const reminderAgentManager::manager::ReminderRequest& reminderReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    if (reminderReq.ringDuration.has_value()) {
        int64_t ringDuration = static_cast<int64_t>(reminderReq.ringDuration.value());
        if (ringDuration < 0 || ringDuration > static_cast<int64_t>(
            Notification::ReminderRequest::MAX_RING_DURATION / Notification::ReminderRequest::MILLI_SECONDS)) {
            ANSR_LOGE("Param[ringDuration] out of range.");
            return false;
        }
        reminder->SetRingDuration(static_cast<uint64_t>(ringDuration));
    }
    if (reminderReq.snoozeTimes.has_value()) {
        int32_t snoozeTimes = static_cast<int32_t>(reminderReq.snoozeTimes.value());
        if (snoozeTimes < 0) {
            reminder->SetSnoozeTimes(0);
        } else {
            reminder->SetSnoozeTimes(snoozeTimes > UINT8_MAX ? UINT8_MAX : static_cast<uint8_t>(snoozeTimes));
        }
    }
    if (reminderReq.timeInterval.has_value()) {
        reminder->SetTimeInterval(static_cast<uint64_t>(reminderReq.timeInterval.value()));
    }
    if (reminderReq.titleResourceId.has_value()) {
        reminder->SetTitleResourceId(static_cast<int32_t>(reminderReq.titleResourceId.value()));
    }
    if (reminderReq.contentResourceId.has_value()) {
        reminder->SetContentResourceId(static_cast<int32_t>(reminderReq.contentResourceId.value()));
    }
    if (reminderReq.expiredContentResourceId.has_value()) {
        reminder->SetExpiredContentResourceId(static_cast<int32_t>(reminderReq.expiredContentResourceId.value()));
    }
    if (reminderReq.snoozeContentResourceId.has_value()) {
        reminder->SetSnoozeContentResourceId(static_cast<int32_t>(reminderReq.snoozeContentResourceId.value()));
    }
    if (reminderReq.notificationId.has_value()) {
        reminder->SetNotificationId(static_cast<int32_t>(reminderReq.notificationId.value()));
    }
    if (reminderReq.autoDeletedTime.has_value()) {
        int64_t autoDeletedTime = static_cast<int64_t>(reminderReq.autoDeletedTime.value());
        reminder->SetAutoDeletedTime(autoDeletedTime > 0 ? autoDeletedTime : 0);
    }
    return true;
}

void Common::ParseStringParam(const reminderAgentManager::manager::ReminderRequest& reminderReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    if (reminderReq.title.has_value()) {
        reminder->SetTitle(reminderReq.title.value().c_str());
    }
    if (reminderReq.content.has_value()) {
        reminder->SetContent(reminderReq.content.value().c_str());
    }
    if (reminderReq.expiredContent.has_value()) {
        reminder->SetExpiredContent(reminderReq.expiredContent.value().c_str());
    }
    if (reminderReq.snoozeContent.has_value()) {
        reminder->SetSnoozeContent(reminderReq.snoozeContent.value().c_str());
    }
    if (reminderReq.groupId.has_value()) {
        reminder->SetGroupId(reminderReq.groupId.value().c_str());
    }
    if (reminderReq.customRingUri.has_value()) {
        reminder->SetCustomRingUri(reminderReq.customRingUri.value().c_str());
    }
}

bool Common::ParseLocalDateTime(const reminderAgentManager::manager::LocalDateTime& dateTimeReq,
    struct tm& dateTime)
{
    int32_t year = static_cast<int32_t>(dateTimeReq.year);
    if (year < 0 || year > UINT16_MAX) {
        ANSR_LOGE("Param[year] out of range[0, %{public}d]", UINT16_MAX);
        return false;
    }
    dateTime.tm_year = Notification::ReminderRequest::GetCTime(
        Notification::ReminderRequest::TimeTransferType::YEAR, year);

    int32_t month = static_cast<int32_t>(dateTimeReq.month);
    if (month < 1 || month > Notification::ReminderRequestCalendar::MAX_MONTHS_OF_YEAR) {
        ANSR_LOGE("Param[month] out of range[1, %{public}hhu]",
            Notification::ReminderRequestCalendar::MAX_MONTHS_OF_YEAR);
        return false;
    }
    dateTime.tm_mon = Notification::ReminderRequest::GetCTime(
        Notification::ReminderRequest::TimeTransferType::MONTH, month);

    uint8_t maxDaysOfMonth = Notification::ReminderRequestCalendar::GetDaysOfMonth(
        static_cast<uint16_t>(year), static_cast<uint8_t>(month));
    int32_t day = static_cast<int32_t>(dateTimeReq.day);
    if ((day < 1) || (day > maxDaysOfMonth)) {
        ANSR_LOGW("Param[day] out of range[1, %{public}hhu]", maxDaysOfMonth);
        return false;
    }
    dateTime.tm_mday = day;

    int32_t hour = static_cast<int32_t>(dateTimeReq.hour);
    if (hour < 0 || hour > MAX_HOUR) {
        ANSR_LOGW("Param[hour] out of range[0, %{public}d]", MAX_HOUR);
        return false;
    }
    dateTime.tm_hour = hour;

    int32_t minute = static_cast<int32_t>(dateTimeReq.minute);
    if (minute < 0 || minute > MAX_MINUTE) {
        ANSR_LOGW("Param[minute] out of range[0, %{public}d]", MAX_MINUTE);
        return false;
    }
    dateTime.tm_min = minute;

    if (dateTimeReq.second.has_value()) {
        dateTime.tm_sec = static_cast<int32_t>(dateTimeReq.second.value());
    } else {
        dateTime.tm_sec = 0;
    }
    dateTime.tm_isdst = -1;
    return true;
}

void Common::ParseWantAgent(const reminderAgentManager::manager::WantAgent& wantAgentReq,
    std::shared_ptr<Notification::ReminderRequest::WantAgentInfo>& wantAgent)
{
    wantAgent = std::make_shared<Notification::ReminderRequest::WantAgentInfo>();
    wantAgent->pkgName = std::string(wantAgentReq.pkgName.c_str());
    wantAgent->abilityName = std::string(wantAgentReq.abilityName.c_str());
    if (wantAgentReq.uri.has_value()) {
        wantAgent->uri = std::string(wantAgentReq.uri.value().c_str());
    }
    if (!wantAgentReq.parameters.has_value()) {
        return;
    }

    for (const auto& [key, value] : wantAgentReq.parameters.value()) {
        switch (value.get_tag()) {
            case reminderAgentManager::manager::ParamType::tag_t::string_t: {
                wantAgent->parameters.SetParam(std::string(key.c_str()),
                    AAFwk::String::Box(std::string(value.get_string_t_ref().c_str())));
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::double_t: {
                wantAgent->parameters.SetParam(std::string(key.c_str()),
                    AAFwk::Double::Box(value.get_double_t_ref()));
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::int_t: {
                wantAgent->parameters.SetParam(std::string(key.c_str()),
                    AAFwk::Integer::Box(value.get_int_t_ref()));
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::bool_t: {
                wantAgent->parameters.SetParam(std::string(key.c_str()),
                    AAFwk::Boolean::Box(value.get_bool_t_ref()));
                break;
            }
            default:
                break;
        }
    }
}

void Common::ParseMaxScreenWantAgent(const reminderAgentManager::manager::MaxScreenWantAgent& wantAgentReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    auto wantAgent = std::shared_ptr<Notification::ReminderRequest::MaxScreenAgentInfo>();
    reminder->SetMaxScreenWantAgentInfo(wantAgent);
    wantAgent->pkgName = std::string(wantAgentReq.pkgName.c_str());
    wantAgent->abilityName = std::string(wantAgentReq.abilityName.c_str());
}

void Common::ParseButtonWantAgent(const reminderAgentManager::manager::WantAgent& wantAgentReq,
    std::shared_ptr<Notification::ReminderRequest::ButtonWantAgent>& buttonWantAgent,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    buttonWantAgent->pkgName = std::string(wantAgentReq.pkgName.c_str());
    buttonWantAgent->abilityName = std::string(wantAgentReq.abilityName.c_str());
    if (wantAgentReq.uri.has_value()) {
        reminder->SetCustomButtonUri(wantAgentReq.uri.value().c_str());
    }
}

void Common::ParseDataShareUpdateEqualTo(
    const ::taihe::map<::taihe::string, reminderAgentManager::manager::ParamType>& aniEqualTo,
    std::string& equalTo)
{
    size_t arrlen = aniEqualTo.size();
    size_t i = 0;
    for (const auto& [key, value] : aniEqualTo) {
        ++i;
        std::string type;
        std::string result;
        switch (value.get_tag()) {
            case reminderAgentManager::manager::ParamType::tag_t::string_t: {
                type = "string";
                result = std::string(value.get_string_t_ref().c_str());
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::double_t: {
                type = "double";
                result = std::to_string(value.get_double_t_ref());
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::int_t: {
                type = "int";
                result = std::to_string(value.get_int_t_ref());
                break;
            }
            case reminderAgentManager::manager::ParamType::tag_t::bool_t: {
                type = "bool";
                result = std::to_string(value.get_bool_t_ref());
                break;
            }
            default:
                break;
        }
        if (type.empty()) {
            continue;
        }
        if (!IsValidateString(std::string(key.c_str())) || !IsValidateString(result)) {
            continue;
        }
        equalTo += key + Notification::ReminderRequest::SEP_BUTTON_VALUE + type
            + Notification::ReminderRequest::SEP_BUTTON_VALUE + result;
        if (i < arrlen) {
            equalTo += Notification::ReminderRequest::SEP_BUTTON_VALUE_TYPE;
        }
    }
}

void Common::ParseButtonDataShareUpdate(
    const reminderAgentManager::manager::DataShareUpdate& aniDataShareUpdate,
    std::shared_ptr<Notification::ReminderRequest::ButtonDataShareUpdate>& dataShareUpdate)
{
    dataShareUpdate->uri = std::string(aniDataShareUpdate.uri.c_str());
    ParseDataShareUpdateEqualTo(aniDataShareUpdate.equalTo, dataShareUpdate->equalTo);
}

bool Common::ParseActionButton(
    const ::taihe::array<::ohos::reminderAgentManager::manager::ActionButton>& actionButtons,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    for (const auto& actionButton : actionButtons) {
        auto buttonType = Notification::ReminderRequest::ActionButtonType::INVALID;
        auto buttonWantAgent = std::make_shared<Notification::ReminderRequest::ButtonWantAgent>();
        switch (actionButton.type.get_key()) {
            case reminderAgentManager::manager::ActionButtonType::key_t::ACTION_BUTTON_TYPE_CLOSE:
                buttonType = Notification::ReminderRequest::ActionButtonType::CLOSE;
                break;
            case reminderAgentManager::manager::ActionButtonType::key_t::ACTION_BUTTON_TYPE_SNOOZE:
                buttonType = Notification::ReminderRequest::ActionButtonType::SNOOZE;
                break;
            case reminderAgentManager::manager::ActionButtonType::key_t::ACTION_BUTTON_TYPE_CUSTOM: {
                if (!IsSelfSystemApp()) {
                    ANSR_LOGW("Not system app, ACTION_BUTTON_TYPE_CUSTOM not supported.");
                    return false;
                }
                buttonType = Notification::ReminderRequest::ActionButtonType::CUSTOM;
                if (actionButton.wantAgent.has_value()) {
                    ParseButtonWantAgent(actionButton.wantAgent.value(), buttonWantAgent, reminder);
                }
                break;
            }
            default:
                continue;
        }
        std::string title = std::string(actionButton.title.c_str());
        std::string resource = "";
        if (actionButton.titleResource.has_value()) {
            resource = std::string(actionButton.titleResource.value().c_str());
        }
        auto buttonDataShareUpdate = std::make_shared<Notification::ReminderRequest::ButtonDataShareUpdate>();
        if (actionButton.dataShareUpdate.has_value()) {
            ParseButtonDataShareUpdate(actionButton.dataShareUpdate.value(), buttonDataShareUpdate);
        }
        reminder->SetActionButton(title, buttonType, resource, buttonWantAgent, buttonDataShareUpdate);
    }
    return true;
}

bool Common::ParseCalendarParam(const ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
    std::vector<uint8_t>& repeatMonths, std::vector<uint8_t>& repeatDays, std::vector<uint8_t>& daysOfWeek)
{
    if (calendarReq.repeatMonths.has_value() && !ParseIntArray(calendarReq.repeatMonths.value(),
        repeatMonths, Notification::ReminderRequestCalendar::MAX_MONTHS_OF_YEAR)) {
        return false;
    }
    if (calendarReq.repeatDays.has_value() && !ParseIntArray(calendarReq.repeatDays.value(),
        repeatDays, Notification::ReminderRequestCalendar::MAX_DAYS_OF_MONTH)) {
        return false;
    }
    if (calendarReq.daysOfWeek.has_value() && !ParseIntArray(calendarReq.daysOfWeek.value(),
        daysOfWeek, MAX_DAYS_OF_WEEK)) {
        return false;
    }
    return true;
}

bool Common::CreateReminderBase(const reminderAgentManager::manager::ReminderRequest& reminderReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    if (!ParseIntParam(reminderReq, reminder)) {
        return false;
    }
    ParseStringParam(reminderReq, reminder);
    if (reminderReq.tapDismissed.has_value()) {
        reminder->SetTapDismissed(reminderReq.tapDismissed.value());
    }
    if (reminderReq.wantAgent.has_value()) {
        std::shared_ptr<Notification::ReminderRequest::WantAgentInfo> wantAgent;
        ParseWantAgent(reminderReq.wantAgent.value(), wantAgent);
        reminder->SetWantAgentInfo(wantAgent);
    }
    if (reminderReq.maxScreenWantAgent.has_value()) {
        ParseMaxScreenWantAgent(reminderReq.maxScreenWantAgent.value(), reminder);
    }
    if (reminderReq.actionButton.has_value()) {
        if (!ParseActionButton(reminderReq.actionButton.value(), reminder)) {
            return false;
        }
    }
    if (reminderReq.slotType.has_value()) {
        Notification::NotificationConstant::SlotType slotType;
        if (!UnWarpSlotType(reminderReq.slotType.value(), slotType)) {
            return false;
        }
        reminder->SetSlotType(slotType);
    }
    if (reminderReq.snoozeSlotType.has_value()) {
        Notification::NotificationConstant::SlotType slotType;
        if (!UnWarpSlotType(reminderReq.snoozeSlotType.value(), slotType)) {
            return false;
        }
        reminder->SetSnoozeSlotType(slotType);
    }
    return true;
}

bool Common::CreateReminderTimer(const reminderAgentManager::manager::ReminderRequestTimer& timerReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    uint64_t triggerTimeInSeconds = static_cast<uint64_t>(timerReq.triggerTimeInSeconds);
    if (triggerTimeInSeconds >= (UINT64_MAX / Notification::ReminderRequest::MILLI_SECONDS)) {
        ANSR_LOGE("Param[triggerTimeInSeconds] out of range.");
        return false;
    }
    auto timer = std::make_shared<Notification::ReminderRequestTimer>(triggerTimeInSeconds);
    reminder = timer;
    if (!CreateReminderBase(timerReq.base, reminder)) {
        reminder = nullptr;
        return false;
    }
    return true;
}

bool Common::CreateReminderAlarm(const reminderAgentManager::manager::ReminderRequestAlarm& alarmReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    int32_t hour = static_cast<int32_t>(alarmReq.hour);
    int32_t minute = static_cast<int32_t>(alarmReq.minute);
    if (hour < 0 || hour > MAX_HOUR) {
        ANSR_LOGE("Param[hour] out of range[0, 23].");
        return false;
    }
    if (minute < 0 || minute > MAX_MINUTE) {
        ANSR_LOGE("Param[minute] out of range[0, 59].");
        return false;
    }
    std::vector<uint8_t> daysOfWeek;
    if (alarmReq.daysOfWeek.has_value() &&
        !ParseIntArray(alarmReq.daysOfWeek.value(), daysOfWeek, MAX_DAYS_OF_WEEK)) {
        return false;
    }
    auto alarm = std::make_shared<Notification::ReminderRequestAlarm>(static_cast<uint8_t>(hour),
        static_cast<uint8_t>(minute), daysOfWeek);
    reminder = alarm;
    if (!CreateReminderBase(alarmReq.base, reminder)) {
        reminder = nullptr;
        return false;
    }
    return true;
}

bool Common::CreateReminderCalendar(const reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
    std::shared_ptr<Notification::ReminderRequest>& reminder)
{
    struct tm dateTime;
    if (!ParseLocalDateTime(calendarReq.dateTime, dateTime)) {
        return false;
    }
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    if (!ParseCalendarParam(calendarReq, repeatMonths, repeatDays, daysOfWeek)) {
        return false;
    }

    std::shared_ptr<Notification::ReminderRequest::WantAgentInfo> rruleWantAgent;
    if (calendarReq.rruleWantAgent.has_value()) {
        ParseWantAgent(calendarReq.rruleWantAgent.value(), rruleWantAgent);
    }
    if (!IsSelfSystemApp() && rruleWantAgent != nullptr) {
        ANS_LOGE("Not system app, rruleWantAgent not supported.");
        return false;
    }
    auto calendar =
        std::make_shared<Notification::ReminderRequestCalendar>(dateTime, repeatMonths, repeatDays, daysOfWeek);
    if (calendarReq.endDateTime.has_value()) {
        struct tm endDateTime;
        if (!ParseLocalDateTime(calendarReq.endDateTime.value(), endDateTime)) {
            return false;
        }
        time_t endTime = mktime(&endDateTime);
        if (endTime == -1) {
            ANS_LOGE("Param[endDateTime] not a valid value.");
            return false;
        }
        if (!calendar->SetEndDateTime(Notification::ReminderRequest::GetDurationSinceEpochInMilli(endTime))) {
            ANSR_LOGW("The endDateTime must be greater than dateTime");
            return false;
        }
    }
    if (!calendar->InitTriggerTime()) {
        return false;
    }
    calendar->SetRRuleWantAgentInfo(rruleWantAgent);
    reminder = calendar;
    if (!CreateReminderBase(calendarReq.base, reminder)) {
        reminder = nullptr;
        return false;
    }
    return true;
}

void Common::GenAniIntResult(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequest& base)
{
    base.ringDuration = ::taihe::optional<double>::make(static_cast<double>(reminder->GetRingDuration()));
    base.snoozeTimes = ::taihe::optional<double>::make(static_cast<double>(reminder->GetSnoozeTimes()));
    base.timeInterval = ::taihe::optional<double>::make(static_cast<double>(reminder->GetTimeInterval()));
    base.titleResourceId = ::taihe::optional<double>::make(static_cast<double>(reminder->GetTitleResourceId()));
    base.contentResourceId = ::taihe::optional<double>::make(static_cast<double>(reminder->GetContentResourceId()));
    base.expiredContentResourceId = ::taihe::optional<double>::make(
        static_cast<double>(reminder->GetExpiredContentResourceId()));
    base.snoozeContentResourceId = ::taihe::optional<double>::make(
        static_cast<double>(reminder->GetSnoozeContentResourceId()));
    base.notificationId = ::taihe::optional<double>::make(static_cast<double>(reminder->GetNotificationId()));
    base.autoDeletedTime = ::taihe::optional<double>::make(static_cast<double>(reminder->GetAutoDeletedTime()));
}

void Common::GenAniStringResult(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequest& base)
{
    base.title = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetTitle()));
    base.content = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetContent()));
    base.expiredContent = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetExpiredContent()));
    base.snoozeContent = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetSnoozeContent()));
    base.groupId = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetGroupId()));
    base.customRingUri = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetCustomRingUri()));
}

void Common::GenAniWantParams(const std::shared_ptr<Notification::ReminderRequest::WantAgentInfo>& wantInfo,
    reminderAgentManager::manager::WantAgent& aniWantAgent)
{
    auto params = wantInfo->parameters.GetParams();
    if (params.size() == 0) {
        return;
    }
    ::taihe::map<::taihe::string, reminderAgentManager::manager::ParamType> aniParams;
    for (const auto& iter : params) {
        int32_t typeId = AAFwk::WantParams::GetDataType(iter.second);
        switch (typeId) {
            case VALUE_TYPE_INT: {
                AAFwk::IInteger* intPtr = AAFwk::IInteger::Query(iter.second);
                if (intPtr != nullptr) {
                    int32_t intVal = AAFwk::Integer::Unbox(intPtr);
                    aniParams.emplace(iter.first, reminderAgentManager::manager::ParamType::make_int_t(intVal));
                }
                break;
            }
            case VALUE_TYPE_DOUBLE: {
                AAFwk::IDouble* doublePtr = AAFwk::IDouble::Query(iter.second);
                if (doublePtr != nullptr) {
                    double doubleVal = AAFwk::Double::Unbox(doublePtr);
                    aniParams.emplace(iter.first, reminderAgentManager::manager::ParamType::make_double_t(doubleVal));
                }
                break;
            }
            case VALUE_TYPE_BOOLEAN: {
                AAFwk::IBoolean *boolPtr = AAFwk::IBoolean::Query(iter.second);
                if (boolPtr != nullptr) {
                    bool boolVal = AAFwk::Boolean::Unbox(boolPtr);
                    aniParams.emplace(iter.first, reminderAgentManager::manager::ParamType::make_bool_t(boolVal));
                }
                break;
            }
            case VALUE_TYPE_STRING: {
                AAFwk::IString *strPtr = AAFwk::IString::Query(iter.second);
                if (strPtr != nullptr) {
                    std::string strVal = AAFwk::String::Unbox(strPtr);
                    aniParams.emplace(iter.first, reminderAgentManager::manager::ParamType::make_string_t(strVal));
                }
                break;
            }
            default: {
                break;
            }
        }
    }
    aniWantAgent.parameters =
        ::taihe::optional<::taihe::map<::taihe::string, reminderAgentManager::manager::ParamType>>::make(aniParams);
}

void Common::GenAniWantAgent(const sptr<Notification::ReminderRequest>& reminder,
    ::taihe::optional<reminderAgentManager::manager::WantAgent>& aniWantAgent)
{
    if (reminder->GetWantAgentInfo() == nullptr) {
        return;
    }
    auto wantAgent = reminder->GetWantAgentInfo();
    reminderAgentManager::manager::WantAgent aniWant {
        .pkgName = ::taihe::string(wantAgent->pkgName),
        .abilityName = ::taihe::string(wantAgent->abilityName),
        .uri = ::taihe::optional<::taihe::string>::make(::taihe::string(wantAgent->uri)),
    };
    GenAniWantParams(wantAgent, aniWant);
    aniWantAgent = ::taihe::optional<reminderAgentManager::manager::WantAgent>::make(aniWant);
}

void Common::GenAniMaxScreenWantAgent(const sptr<Notification::ReminderRequest>& reminder,
    ::taihe::optional<reminderAgentManager::manager::MaxScreenWantAgent>& aniWantAgent)
{
    if (reminder->GetMaxScreenWantAgentInfo() == nullptr) {
        return;
    }
    auto wantAgent = reminder->GetMaxScreenWantAgentInfo();
    reminderAgentManager::manager::MaxScreenWantAgent aniWant {
        .pkgName = ::taihe::string(wantAgent->pkgName),
        .abilityName = ::taihe::string(wantAgent->abilityName),
    };
    aniWantAgent = ::taihe::optional<reminderAgentManager::manager::MaxScreenWantAgent>::make(aniWant);
}

void Common::GenAniActionButton(const sptr<Notification::ReminderRequest>& reminder,
    ::taihe::optional<::taihe::array<reminderAgentManager::manager::ActionButton>>& aniActionButtons)
{
    auto actionButtons = reminder->GetActionButtons();
    if (actionButtons.empty()) {
        return;
    }
    std::vector<reminderAgentManager::manager::ActionButton> aniButtons;
    for (const auto& [type, actionButton] : actionButtons) {
        reminderAgentManager::manager::ActionButton aniActionButton {
            .type = static_cast<reminderAgentManager::manager::ActionButtonType::key_t>(type),
        };
        aniActionButton.title = ::taihe::string(actionButton.title);
        aniActionButton.titleResource = ::taihe::optional<::taihe::string>::make(
            ::taihe::string(actionButton.resource));
        if (type == Notification::ReminderRequest::ActionButtonType::CUSTOM && actionButton.wantAgent != nullptr) {
            reminderAgentManager::manager::WantAgent wantAgent {
                .pkgName = ::taihe::string(actionButton.wantAgent->pkgName),
                .abilityName = ::taihe::string(actionButton.wantAgent->abilityName),
            };
            wantAgent.uri = ::taihe::optional<::taihe::string>::make(::taihe::string(reminder->GetCustomButtonUri()));
            aniActionButton.wantAgent = ::taihe::optional<reminderAgentManager::manager::WantAgent>::make(wantAgent);
        }
        aniButtons.push_back(aniActionButton);
    }
    aniActionButtons = ::taihe::optional<::taihe::array<reminderAgentManager::manager::ActionButton>>::make(aniButtons);
}

void Common::GenAniReminderBase(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequest& base)
{
    GenAniIntResult(reminder, base);
    GenAniStringResult(reminder, base);
    base.tapDismissed = ::taihe::optional<bool>::make(reminder->IsTapDismissed());
    GenAniWantAgent(reminder, base.wantAgent);
    GenAniMaxScreenWantAgent(reminder, base.maxScreenWantAgent);
    GenAniActionButton(reminder, base.actionButton);
}

void Common::GenAniReminderTimer(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequestTimer& timer)
{
    GenAniReminderBase(reminder, timer.base);
    Notification::ReminderRequestTimer* timerReq =
        static_cast<Notification::ReminderRequestTimer*>(reminder.GetRefPtr());
    timer.triggerTimeInSeconds = static_cast<double>(timerReq->GetInitInfo());
}

void Common::GenAniReminderAlarm(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequestAlarm& alarm)
{
    GenAniReminderBase(reminder, alarm.base);
    Notification::ReminderRequestAlarm* alarmReq =
        static_cast<Notification::ReminderRequestAlarm*>(reminder.GetRefPtr());
    alarm.hour = static_cast<double>(alarmReq->GetHour());
    alarm.minute = static_cast<double>(alarmReq->GetMinute());
    auto daysOfWeek = reminder->GetDaysOfWeek();
    if (daysOfWeek.empty()) {
        return;
    }
    std::vector<double> results = ConvertInt<int32_t>(daysOfWeek);
    alarm.daysOfWeek = ::taihe::optional<::taihe::array<double>>::make(results);
}

void Common::GenAniReminderCalendar(const sptr<Notification::ReminderRequest>& reminder,
    reminderAgentManager::manager::ReminderRequestCalendar& calendar)
{
    GenAniReminderBase(reminder, calendar.base);
    Notification::ReminderRequestCalendar* calendarReq =
        static_cast<Notification::ReminderRequestCalendar*>(reminder.GetRefPtr());
    calendar.dateTime.year = static_cast<double>(calendarReq->GetFirstDesignateYear());
    calendar.dateTime.month = static_cast<double>(calendarReq->GetFirstDesignageMonth());
    calendar.dateTime.day = static_cast<double>(calendarReq->GetFirstDesignateDay());
    calendar.dateTime.hour = static_cast<double>(calendarReq->GetHour());
    calendar.dateTime.minute = static_cast<double>(calendarReq->GetMinute());
    calendar.dateTime.second = ::taihe::optional<double>::make(static_cast<double>(calendarReq->GetSecond()));
    auto months = calendarReq->GetRepeatMonths();
    if (!months.empty()) {
        std::vector<double> results = ConvertInt<uint8_t>(months);
        calendar.repeatMonths = ::taihe::optional<::taihe::array<double>>::make(results);
    }
    auto days = calendarReq->GetRepeatDays();
    if (!days.empty()) {
        std::vector<double> results = ConvertInt<uint8_t>(days);
        calendar.repeatDays = ::taihe::optional<::taihe::array<double>>::make(results);
    }
    auto daysOfWeek = reminder->GetDaysOfWeek();
    if (!daysOfWeek.empty()) {
        std::vector<double> results = ConvertInt<int32_t>(daysOfWeek);
        calendar.daysOfWeek = ::taihe::optional<::taihe::array<double>>::make(results);
    }
}

bool Common::IsSelfSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}
}