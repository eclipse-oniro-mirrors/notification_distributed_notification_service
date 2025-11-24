/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMINDER_COMMON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMINDER_COMMON_H

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "reminder_helper.h"
#include "reminder_request.h"
#include "reminder_request_calendar.h"

namespace OHOS {
namespace ReminderAgentNapi {
using namespace OHOS::Notification;

namespace {
const char* ACTION_BUTTON = "actionButton";
const char* ACTION_BUTTON_TITLE = "title";
const char* ACTION_BUTTON_TYPE = "type";
const char* ACTION_BUTTON_RESOURCE = "titleResource";
const char* ALARM_HOUR = "hour";
const char* REPEAT_DAYS_OF_WEEK = "daysOfWeek";
const char* ALARM_MINUTE = "minute";
const char* CALENDAR_END_DATE_TIME = "endDateTime";
const char* CALENDAR_DATE_TIME = "dateTime";
const char* CALENDAR_YEAR = "year";
const char* CALENDAR_MONTH = "month";
const char* CALENDAR_DAY = "day";
const char* CALENDAR_HOUR = "hour";
const char* CALENDAR_MINUTE = "minute";
const char* CALENDAR_SECOND = "second";
const char* CALENDAR_REPEAT_MONTHS = "repeatMonths";
const char* CALENDAR_REPEAT_DAYS = "repeatDays";
const char* CONTENT = "content";
const char* CONTENT_RESOURCE_ID = "contentResourceId";
const char* EXPIRED_CONTENT = "expiredContent";
const char* EXPIRED_CONTENT_RESOURCE_ID = "expiredContentResourceId";
const char* MAX_SCREEN_WANT_AGENT = "maxScreenWantAgent";
const char* MAX_SCREEN_WANT_AGENT_PKG = "pkgName";
const char* MAX_SCREEN_WANT_AGENT_ABILITY = "abilityName";
const char* NOTIFICATION_ID = "notificationId";
const char* REMINDER_TYPE = "reminderType";
const char* RING_DURATION = "ringDuration";
const char* SLOT_TYPE = "slotType";
const char* SNOOZE_CONTENT = "snoozeContent";
const char* SNOOZE_CONTENT_RESOURCE_ID = "snoozeContentResourceId";
const char* SNOOZE_TIMES = "snoozeTimes";
const char* TIME_INTERVAL = "timeInterval";
const char* TITLE = "title";
const char* TITLE_RESOURCE_ID = "titleResourceId";
const char* TIMER_COUNT_DOWN_TIME = "triggerTimeInSeconds";
const char* WANT_AGENT = "wantAgent";
const char* RRULL_WANT_AGENT = "rruleWantAgent";
const char* WANT_AGENT_PKG = "pkgName";
const char* WANT_AGENT_ABILITY = "abilityName";
const char* WANT_AGENT_URI = "uri";
const char* WANT_AGENT_PARAMETERS = "parameters";
const char* BUTTON_WANT_AGENT = "wantAgent";
const char* BUTTON_WANT_AGENT_PKG = "pkgName";
const char* BUTTON_WANT_AGENT_ABILITY = "abilityName";
const char* BUTTON_WANT_AGENT_URI = "uri";
const char* BUTTON_DATA_SHARE_UPDATE = "dataShareUpdate";
const char* BUTTON_DATA_SHARE_UPDATE_URI = "uri";
const char* BUTTON_DATA_SHARE_UPDATE_EQUALTO = "equalTo";
const char* BUTTON_DATA_SHARE_UPDATE_VALUE = "value";
const char* TAPDISMISSED = "tapDismissed";
const char* AUTODELETEDTIME = "autoDeletedTime";
const char* GROUP_ID = "groupId";
const char* CUSTOM_RING_URI = "customRingUri";
const char* RING_CHANNEL = "ringChannel";
const char* SNOOZE_SLOT_TYPE = "snoozeSlotType";
const char* REMINDER_INFO_REMINDER_REQ = "reminderReq";
const char* REMINDER_INFO_REMINDER_ID = "reminderId";
const char* REMINDER_FORCE_DISTRIBUTED = "forceDistributed";
const char* REMINDER_NOT_DISTRIBUTED = "notDistributed";
const int INDEX_KEY = 0;
const int INDEX_TYPE = 1;
const int INDEX_VALUE = 2;
}

struct CallbackPromiseInfo {
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    bool isCallback = false;
    int32_t errorCode = 0;
};

class ReminderCommon {
    ReminderCommon();
    ~ReminderCommon();
    ReminderCommon(ReminderCommon &other) = delete;
    ReminderCommon& operator = (const ReminderCommon &other) = delete;

public:
    static napi_value GetReminderRequest(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static bool GetStringUtf8(const napi_env &env, const napi_value &value,
        const char* propertyName, char* propertyVal, const int32_t size);

    static bool GetBool(const napi_env &env, const napi_value &value,
        const char* propertyName, bool& propertyVal);

    static bool GetInt32(const napi_env &env, const napi_value &value,
        const char* propertyName, int32_t& propertyVal, bool isNecessary);

    static bool GetInt64(const napi_env &env, const napi_value &value,
        const char* propertyName, int64_t& propertyVal);

    static bool GetObject(const napi_env &env, const napi_value &value,
        const char* propertyName, napi_value& propertyVal);

    static bool GetDate(const napi_env& env, const napi_value& value,
        const char* propertyName, double& date);

    static void HandleErrCode(const napi_env &env, int32_t errCode);

    static void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info,
        const napi_value &result, bool isThrow = false);

    static void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int32_t &errorCode,
        const napi_value &result);

    static napi_value  SetPromise(const napi_env &env, const CallbackPromiseInfo &info,
        const napi_value &result);

    static napi_value JSParaError(const napi_env &env, const napi_ref &callback);

    static void PaddingCallbackPromiseInfo(const napi_env &env, const napi_ref &callback,
        CallbackPromiseInfo &info, napi_value &promise);

private:
    static bool ParseBoolParam(const napi_env& env, const napi_value& value, const bool isSystemApp,
        std::shared_ptr<ReminderRequest>& reminder);

    static bool ParseRingChannel(const napi_env& env, const napi_value& value,
        std::shared_ptr<ReminderRequest>& reminder);

private:
    static bool CheckCalendarParams(const int32_t &year, const int32_t &month, const int32_t &day,
        const int32_t &hour, const int32_t &min);

    static bool ParseCalendarParams(const napi_env& env, const napi_value& value, std::vector<uint8_t>& repeatMonths,
        std::vector<uint8_t>& repeatDays, std::vector<uint8_t> &daysOfWeek);

    static bool ParseLocalDateTime(const napi_env& env, const napi_value& dateTimeObj, struct tm& dateTime);
   
    static napi_value CreateReminderTimer(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static napi_value CreateReminderAlarm(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static napi_value CreateReminderCalendar(
        const napi_env &env, const napi_value &value, const bool isSysApp, std::shared_ptr<ReminderRequest>& reminder);

    static bool CreateReminder(
        const napi_env &env, const napi_value &value,  const bool isSysApp, std::shared_ptr<ReminderRequest>& reminder);

    static bool GetPropertyValIfExist(const napi_env &env, const napi_value &value,
        const char* propertyName, napi_value& propertyVal);

    static bool GenWantAgent(const napi_env &env, const napi_value &value, const char* name,
        std::shared_ptr<ReminderRequest::WantAgentInfo>& wantAgentInfo);

    static void GenMaxScreenWantAgent(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static bool GenActionButtons(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder, bool isSysApp);

    static napi_value GenReminder(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static void HandleActionButtonTitle(const napi_env &env, const napi_value &actionButton,
        std::shared_ptr<ReminderRequest>& reminder, const char* str, int32_t buttonType);

    static void GenReminderStringInner(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static bool GenReminderIntInner(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static bool GenReminderIntInnerOther(
        const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder);

    static napi_value ParseInt32Array(const napi_env &env, const napi_value &value,
        const char* propertyName, std::vector<uint8_t> &propertyVal, uint8_t maxLen);

    static std::string FindErrMsg(const napi_env &env, const int32_t errCode);

    static napi_value GetCallbackErrorValue(napi_env env, const int32_t errCode, const std::string errMsg);

    static void GetButtonWantAgent(const napi_env &env, const napi_value &value,
        std::shared_ptr<ReminderRequest>& reminder, std::shared_ptr<ReminderRequest::ButtonWantAgent>& wantAgent);

    static void GetButtonDataShareUpdate(const napi_env &env, const napi_value &value,
        std::shared_ptr<ReminderRequest::ButtonDataShareUpdate>& buttonDataShareUpdate);

    static bool GetValueBucketObject(std::string &ValueBucketString, const napi_env &env, const napi_value &arg);

    static std::string GetStringFromJS(const napi_env &env, const napi_value &param,
        const std::string &defaultValue = "");

    static std::string Convert2Value(const napi_env &env, const napi_value &value, bool &status, std::string &type);

    static std::vector<uint8_t> Convert2U8Vector(const napi_env &env, const napi_value &input_array);

    static bool ValidateString(const std::string &str);

    static bool IsSelfSystemApp();
};
}  // namespace OHOS
}  // namespace ReminderAgentNapi

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMINDER_COMMON_H
