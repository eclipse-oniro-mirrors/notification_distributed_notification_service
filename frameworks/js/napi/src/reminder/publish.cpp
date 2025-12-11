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

#include "reminder/publish.h"
#include "reminder/reminder_state_listener.h"

#include "ans_log_wrapper.h"
#include "common.h"
#include "napi_common.h"
#include "reminder_request.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "securec.h"

namespace OHOS {
namespace ReminderAgentNapi {
static const int32_t PUBLISH_PARAM_LEN = 2;
static const int32_t CANCEL_PARAM_LEN = 2;
static const int32_t CANCEL_ALL_PARAM_LEN = 1;
static const int32_t GET_VALID_PARAM_LEN = 1;
static const int32_t ADD_SLOT_PARAM_LEN = 2;
static constexpr int32_t ADD_EXCLUDE_DATE_PARAM_LEN = 2;
static constexpr int32_t DEL_EXCLUDE_DATE_PARAM_LEN = 1;
static constexpr int32_t UPDATE_REMINDER_PARAM_LEN = 2;

struct AsyncCallbackInfo {
    explicit AsyncCallbackInfo(napi_env napiEnv) : env(napiEnv) {}
    ~AsyncCallbackInfo()
    {
        if (asyncWork) {
            napi_delete_async_work(env, asyncWork);
            asyncWork = nullptr;
        }
        if (callback) {
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
    }

    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref callback = nullptr;
    napi_value result = nullptr;
    int32_t reminderId = -1;
    int64_t excludeDate = 0;
    bool isThrow = false;
    NotificationNapi::NotificationConstant::SlotType inType
        = NotificationNapi::NotificationConstant::SlotType::CONTENT_INFORMATION;
    std::shared_ptr<ReminderRequest> reminder = nullptr;
    std::vector<ReminderRequestAdaptation> validReminders;
    std::vector<int64_t> excludeDates;
    CallbackPromiseInfo info;
};

struct Parameters {
    int32_t reminderId = -1;
    int64_t excludeDate = 0;
    int32_t errCode = ERR_OK;
    NotificationNapi::NotificationConstant::SlotType inType
        = NotificationNapi::NotificationConstant::SlotType::CONTENT_INFORMATION;
    std::shared_ptr<ReminderRequest> reminder = nullptr;
};

napi_value GetCallback(const napi_env &env, const napi_value &value, AsyncCallbackInfo &asyncCallbackInfo)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_function) {
        ANSR_LOGE("Wrong argument type. Function expected.");
        return nullptr;
    }
    napi_create_reference(env, value, 1, &asyncCallbackInfo.callback);
    return NotificationNapi::Common::NapiGetNull(env);
}

void SetAsynccallbackinfo(const napi_env &env, AsyncCallbackInfo& asynccallbackinfo, napi_value& promise)
{
    ReminderCommon::PaddingCallbackPromiseInfo(
        env, asynccallbackinfo.callback, asynccallbackinfo.info, promise);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, Parameters &params,
    AsyncCallbackInfo &asyncCallbackInfo, bool isThrow)
{
    size_t argc = PUBLISH_PARAM_LEN;
    napi_value argv[PUBLISH_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < 1) {
        ANSR_LOGE("Wrong number of arguments");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }

    // argv[1]: callback
    if (argc >= PUBLISH_PARAM_LEN) {
        if (GetCallback(env, argv[1], asyncCallbackInfo) == nullptr) {
            ANSR_LOGE("null GetCallback");
            if (isThrow) {
                ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
            }
            return nullptr;
        }
    }

    // argv[0] : reminderRequest
    if (ReminderCommon::GetReminderRequest(env, argv[0], params.reminder) == nullptr) {
        ANSR_LOGE("null GetReminderRequest");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }

    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ParseSlotParameters(const napi_env &env, const napi_callback_info &info, Parameters &params,
    AsyncCallbackInfo &asyncCallbackInfo, bool isThrow)
{
    size_t argc = ADD_SLOT_PARAM_LEN;
    napi_value argv[ADD_SLOT_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < 1) {
        ANSR_LOGE("Wrong number of arguments");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }

    // argv[1]: callback
    if (argc >= ADD_SLOT_PARAM_LEN) {
        if (GetCallback(env, argv[1], asyncCallbackInfo) == nullptr) {
            ANSR_LOGE("null GetCallback");
            if (isThrow) {
                ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
            }
            return nullptr;
        }
    }

    // argv[0] : notificationSlot
    // slotType
    const char* propertyKey = "type";
    const char* propertyNewKey = "notificationType";
    int32_t propertyVal = 0;
    if (!ReminderCommon::GetInt32(env, argv[0], propertyKey, propertyVal, false) &&
        !ReminderCommon::GetInt32(env, argv[0], propertyNewKey, propertyVal, false)) {
            ANSR_LOGE("Failed to get valid slot type.");
        params.errCode = ERR_REMINDER_INVALID_PARAM;
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }

    if (!NotificationNapi::AnsEnumUtil::SlotTypeJSToC(NotificationNapi::SlotType(propertyVal), params.inType)) {
        ANSR_LOGE("Failed to get valid slot type");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ParseCanCelParameter(const napi_env &env, const napi_callback_info &info, Parameters &params,
    AsyncCallbackInfo &asyncCallbackInfo, bool isThrow)
{
    ANSR_LOGD("called");
    size_t argc = CANCEL_PARAM_LEN;
    napi_value argv[CANCEL_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < 1) {
        ANSR_LOGE("Wrong number of arguments");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }

    // argv[1]: callback
    if (argc >= CANCEL_PARAM_LEN) {
        if (GetCallback(env, argv[1], asyncCallbackInfo) == nullptr) {
            ANSR_LOGE("null GetCallback");
            if (isThrow) {
                ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
            }
            return nullptr;
        }
    }

    // argv[0]: reminder id
    int32_t reminderId = -1;
    if (!ReminderCommon::GetInt32(env, argv[0], nullptr, reminderId, true)) {
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }
    if (reminderId < 0) {
        ANSR_LOGE("Param id of cancels Reminder is illegal.");
        if (isThrow) {
            ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        }
        return nullptr;
    }
    params.reminderId = reminderId;

    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ParseCanCelAllParameter(const napi_env &env, const napi_callback_info &info, Parameters &params,
    AsyncCallbackInfo &asyncCallbackInfo, bool isThrow)
{
    ANSR_LOGD("called");
    size_t argc = CANCEL_ALL_PARAM_LEN;
    napi_value argv[CANCEL_ALL_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    // argv[0]: callback
    if (argc >= CANCEL_ALL_PARAM_LEN) {
        if (GetCallback(env, argv[0], asyncCallbackInfo) == nullptr) {
            ANSR_LOGE("null GetCallback");
            if (isThrow) {
                ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
            }
            return nullptr;
        }
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ParseGetValidParameter(const napi_env &env, const napi_callback_info &info, Parameters &params,
    AsyncCallbackInfo &asyncCallbackInfo, bool isThrow)
{
    size_t argc = GET_VALID_PARAM_LEN;
    napi_value argv[GET_VALID_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    // argv[0]: callback
    if (argc >= GET_VALID_PARAM_LEN) {
        if (GetCallback(env, argv[0], asyncCallbackInfo) == nullptr) {
            ANSR_LOGE("null GetCallback");
            if (isThrow) {
                ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
            }
            return nullptr;
        }
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value DealErrorReturn(const napi_env &env, const napi_ref &callbackIn, const napi_value &result, bool isThrow)
{
    if (isThrow) {
        return nullptr;
    }
    if (callbackIn) {
        NotificationNapi::Common::SetCallback(env, callbackIn, ERR_REMINDER_INVALID_PARAM,
            result, false);
    }
    return NotificationNapi::Common::JSParaError(env, callbackIn);
}

napi_value CancelReminderInner(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseCanCelParameter(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), isThrow);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->isThrow = isThrow;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelReminder", NAPI_AUTO_LENGTH, &resourceName);

    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("Cancel napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::CancelReminder(asynccallbackinfo->reminderId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("Cancel napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGI("Cancel napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CancelReminderMgr(napi_env env, napi_callback_info info)
{
    return CancelReminderInner(env, info, true);
}

napi_value CancelReminder(napi_env env, napi_callback_info info)
{
    return CancelReminderInner(env, info, false);
}

napi_value CancelAllRemindersInner(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseCanCelAllParameter(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), isThrow);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->isThrow = isThrow;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelAllReminders", NAPI_AUTO_LENGTH, &resourceName);

    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("CancelAll napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::CancelAllReminders();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGD("CancelAll napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGD("CancelAll napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CancelAllRemindersMgr(napi_env env, napi_callback_info info)
{
    return CancelAllRemindersInner(env, info, true);
}

napi_value CancelAllReminders(napi_env env, napi_callback_info info)
{
    return CancelAllRemindersInner(env, info, false);
}

void ParseReminderTimer(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    napi_value value = nullptr;
    ReminderRequestTimer& timer = (ReminderRequestTimer&)reminder;
    napi_create_uint32(env, timer.GetInitInfo(), &value);
    napi_set_named_property(env, result, TIMER_COUNT_DOWN_TIME, value);
}

void ParseReminderAlarm(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    // hour
    napi_value value = nullptr;
    ReminderRequestAlarm& alarm = (ReminderRequestAlarm&)reminder;
    napi_create_uint32(env, static_cast<uint32_t>(alarm.GetHour()), &value);
    napi_set_named_property(env, result, ALARM_HOUR, value);

    // minute
    napi_create_uint32(env, static_cast<uint32_t>(alarm.GetMinute()), &value);
    napi_set_named_property(env, result, ALARM_MINUTE, value);

    // daysOfWeek
    napi_create_array(env, &value);
    napi_set_named_property(env, result, REPEAT_DAYS_OF_WEEK, value);
    int32_t count = 0;
    for (auto day : reminder.GetDaysOfWeek()) {
        if (day) {
            napi_value napiDay = nullptr;
            napi_create_int32(env, day, &napiDay);
            napi_set_element(env, value, count, napiDay);
            count++;
        }
    }
}

void ParseReminderCalendar(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    // dateTime
    napi_value value = nullptr;
    ReminderRequestCalendar& calendar = (ReminderRequestCalendar&)reminder;
    napi_value dateTime = nullptr;
    napi_create_object(env, &dateTime);
    napi_set_named_property(env, result, CALENDAR_DATE_TIME, dateTime);

    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetFirstDesignateYear()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_YEAR, value);
    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetFirstDesignageMonth()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_MONTH, value);
    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetFirstDesignateDay()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_DAY, value);
    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetHour()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_HOUR, value);
    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetMinute()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_MINUTE, value);
    napi_create_uint32(env, static_cast<uint32_t>(calendar.GetSecond()), &value);
    napi_set_named_property(env, dateTime, CALENDAR_SECOND, value);

    // repeatMonths
    napi_create_array(env, &value);
    napi_set_named_property(env, result, CALENDAR_REPEAT_MONTHS, value);
    int32_t count = 0;
    for (auto month : calendar.GetRepeatMonths()) {
        napi_value napiDay = nullptr;
        napi_create_int32(env, month, &napiDay);
        napi_set_element(env, value, count, napiDay);
        count++;
    }

    // repeatDays
    napi_create_array(env, &value);
    napi_set_named_property(env, result, CALENDAR_REPEAT_DAYS, value);
    count = 0;
    for (auto day : calendar.GetRepeatDays()) {
        napi_value napiDay = nullptr;
        napi_create_int32(env, day, &napiDay);
        napi_set_element(env, value, count, napiDay);
        count++;
    }

    // daysOfWeek
    napi_create_array(env, &value);
    napi_set_named_property(env, result, REPEAT_DAYS_OF_WEEK, value);
    count = 0;
    for (auto day : reminder.GetDaysOfWeek()) {
        if (day) {
            napi_value napiDay = nullptr;
            napi_create_int32(env, day, &napiDay);
            napi_set_element(env, value, count, napiDay);
            count++;
        }
    }
}

void ParseReminder(
    const napi_env &env, const ReminderRequest::ReminderType &type, ReminderRequest &reminder, napi_value &result)
{
    switch (type) {
        case ReminderRequest::ReminderType::TIMER: {
            ParseReminderTimer(env, reminder, result);
            break;
        }
        case ReminderRequest::ReminderType::ALARM: {
            ParseReminderAlarm(env, reminder, result);
            break;
        }
        case ReminderRequest::ReminderType::CALENDAR: {
            ParseReminderCalendar(env, reminder, result);
            break;
        }
        default: {
            break;
        }
    }
}

napi_status ParseArray(const napi_env &env, std::vector<std::string>& temp, napi_value &jsObject)
{
    if (temp.size() <= INDEX_VALUE) {
        return napi_invalid_arg;
    }
    // key
    napi_value keyInfo = nullptr;
    napi_create_string_utf8(env, temp[INDEX_KEY].c_str(), NAPI_AUTO_LENGTH, &keyInfo);
    // value
    napi_value valueInfo = nullptr;
    napi_status status = napi_ok;
    if (temp[INDEX_TYPE] == "string") {
        napi_create_string_utf8(env, temp[INDEX_VALUE].c_str(), NAPI_AUTO_LENGTH, &valueInfo);
    } else if (temp[INDEX_TYPE] == "double") {
        napi_create_double(env, ReminderRequest::StringToDouble(temp[INDEX_VALUE]), &valueInfo);
    } else if (temp[INDEX_TYPE] == "bool") {
        bool valueBool = false;
        if (temp[INDEX_VALUE] == "1" || temp[INDEX_VALUE] == "true" || temp[INDEX_VALUE] == "True") {
            valueBool = true;
        }
        napi_get_boolean(env, valueBool, &valueInfo);
    } else if (temp[INDEX_TYPE] == "null") {
        napi_get_null(env, &valueInfo);
    } else if (temp[INDEX_TYPE] == "vector") {
        std::vector<std::string> arr = ReminderRequest::StringSplit(temp[INDEX_VALUE],
            ReminderRequest::SEP_BUTTON_VALUE_BLOB);
        std::vector<uint8_t> value;
        for (auto &num : arr) {
            value.push_back(static_cast<uint8_t>(ReminderRequest::StringToInt(num)));
        }
        // vector<uint8_t> to napi_value
        if (value.size() <= 0) {
            return napi_invalid_arg;
        }
        void* data = nullptr;
        napi_value buffer = nullptr;
        status = napi_create_arraybuffer(env, value.size(), &data, &buffer);
        if (status != napi_ok) {
            ANSR_LOGW("create array buffer failed!");
            return napi_invalid_arg;
        }
        if (memcpy_s(data, value.size(), value.data(), value.size()) != EOK) {
            ANSR_LOGW("memcpy_s not EOK");
            return napi_invalid_arg;
        }
        status = napi_create_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &valueInfo);
        if (status != napi_ok) {
            ANSR_LOGW("napi_create_typedarray failed!");
            return napi_invalid_arg;
        }
    }
    // write keyInfo and valueInfo
    napi_set_property(env, jsObject, keyInfo, valueInfo);
    return status;
}

// parse equalTo,valueBucket
void ParseValueBucket(const napi_env &env, std::vector<std::string> valueBucketVector,
    napi_value &result, const std::string &arrayName)
{
    // create array
    napi_value array = nullptr;
    napi_create_array(env, &array);
    napi_set_named_property(env, result, arrayName.c_str(), array);
    int32_t index = 0;
    // write equalTo or valuesBucket
    for (auto &str : valueBucketVector) {
        std::vector<std::string> temp = ReminderRequest::StringSplit(str, ReminderRequest::SEP_BUTTON_VALUE);
        if (temp.size() <= INDEX_VALUE) {
            continue;
        }
        // key:value
        napi_value jsObject = nullptr;
        napi_create_object(env, &jsObject);
        napi_status status = ParseArray(env, temp, jsObject);
        if (status != napi_ok) {
            continue;
        }
        // write object to array
        napi_set_element(env, array, index++, jsObject);
    }
}

// parse uri,equalTo,valuesBucket  c++ -> js
void ParseButtonDataShareUpdate(const napi_env &env,
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate> &dataShareUpdate, napi_value &result)
{
    // create obj
    napi_value buttonDataShareUpdate = nullptr;
    napi_create_object(env, &buttonDataShareUpdate);
    napi_set_named_property(env, result, BUTTON_DATA_SHARE_UPDATE, buttonDataShareUpdate);
    // uri
    napi_value uriInfo = nullptr;
    napi_create_string_utf8(env, dataShareUpdate->uri.c_str(), NAPI_AUTO_LENGTH, &uriInfo);
    napi_set_named_property(env, buttonDataShareUpdate, BUTTON_DATA_SHARE_UPDATE_URI, uriInfo);
    // equalTo
    std::vector<std::string> equalToVector = ReminderRequest::StringSplit(dataShareUpdate->equalTo,
        ReminderRequest::SEP_BUTTON_VALUE_TYPE);
    ParseValueBucket(env, equalToVector, buttonDataShareUpdate, BUTTON_DATA_SHARE_UPDATE_EQUALTO);
    // valuesBucket
    std::vector<std::string> valuesBucketVector = ReminderRequest::StringSplit(dataShareUpdate->valuesBucket,
        ReminderRequest::SEP_BUTTON_VALUE_TYPE);
    ParseValueBucket(env, valuesBucketVector, buttonDataShareUpdate, BUTTON_DATA_SHARE_UPDATE_VALUE);
}

void ParseActionButtons(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    auto actionButtonsMap = reminder.GetActionButtons();

    // create array
    napi_value array = nullptr;
    napi_create_array(env, &array);
    napi_set_named_property(env, result, ACTION_BUTTON, array);
    int32_t index = 0;
    for (std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>::iterator it
        = actionButtonsMap.begin(); it != actionButtonsMap.end(); ++it) {
        // create obj
        napi_value actionButton = nullptr;
        napi_create_object(env, &actionButton);

        napi_value buttonInfo = nullptr;
        napi_create_uint32(env, static_cast<int32_t>(it->second.type), &buttonInfo);
        napi_set_named_property(env, actionButton, ACTION_BUTTON_TYPE, buttonInfo);
        napi_create_string_utf8(env, (it->second.title).c_str(), NAPI_AUTO_LENGTH, &buttonInfo);
        napi_set_named_property(env, actionButton, ACTION_BUTTON_TITLE, buttonInfo);
        napi_create_string_utf8(env, (it->second.resource).c_str(), NAPI_AUTO_LENGTH, &buttonInfo);
        napi_set_named_property(env, actionButton, ACTION_BUTTON_RESOURCE, buttonInfo);

        // create obj
        napi_value wantAgentInfo = nullptr;
        napi_create_object(env, &wantAgentInfo);
        napi_set_named_property(env, actionButton, WANT_AGENT, wantAgentInfo);

        if (it->second.type == ReminderRequest::ActionButtonType::CUSTOM) {
            napi_value info = nullptr;
            napi_create_string_utf8(env, (it->second.wantAgent->pkgName).c_str(), NAPI_AUTO_LENGTH, &info);
            napi_set_named_property(env, wantAgentInfo, WANT_AGENT_PKG, info);
            napi_create_string_utf8(env, (it->second.wantAgent->abilityName).c_str(), NAPI_AUTO_LENGTH, &info);
            napi_set_named_property(env, wantAgentInfo, WANT_AGENT_ABILITY, info);
            napi_create_string_utf8(env, (reminder.GetCustomButtonUri()).c_str(), NAPI_AUTO_LENGTH, &info);
            napi_set_named_property(env, wantAgentInfo, BUTTON_WANT_AGENT_URI, info);
        }
        // Parse ButtonDataShareUpdate
        if (it->second.type != ReminderRequest::ActionButtonType::INVALID) {
            ParseButtonDataShareUpdate(env, it->second.dataShareUpdate, actionButton);
        }
        // add obj to array
        napi_set_element(env, array, index, actionButton);
        index++;
    }
}

void ParseWantAgent(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    // create obj
    napi_value wantAgentInfo = nullptr;
    napi_create_object(env, &wantAgentInfo);
    napi_set_named_property(env, result, WANT_AGENT, wantAgentInfo);

    napi_value info = nullptr;
    napi_create_string_utf8(env, (reminder.GetWantAgentInfo()->pkgName).c_str(), NAPI_AUTO_LENGTH, &info);
    napi_set_named_property(env, wantAgentInfo, WANT_AGENT_PKG, info);
    napi_create_string_utf8(env, (reminder.GetWantAgentInfo()->abilityName).c_str(), NAPI_AUTO_LENGTH, &info);
    napi_set_named_property(env, wantAgentInfo, WANT_AGENT_ABILITY, info);

    napi_create_string_utf8(env, (reminder.GetWantAgentInfo()->uri).c_str(), NAPI_AUTO_LENGTH, &info);
    napi_set_named_property(env, wantAgentInfo, WANT_AGENT_URI, info);

    napi_value params = AppExecFwk::WrapWantParams(env, reminder.GetWantAgentInfo()->parameters);
    napi_set_named_property(env, wantAgentInfo, WANT_AGENT_PARAMETERS, params);
}

void ParseMaxScreenWantAgent(const napi_env &env, const ReminderRequest &reminder, napi_value &result)
{
    // create obj
    napi_value maxScreenWantAgentInfo = nullptr;
    napi_create_object(env, &maxScreenWantAgentInfo);
    napi_set_named_property(env, result, MAX_SCREEN_WANT_AGENT, maxScreenWantAgentInfo);

    napi_value info = nullptr;
    napi_create_string_utf8(env, (reminder.GetMaxScreenWantAgentInfo()->pkgName).c_str(), NAPI_AUTO_LENGTH, &info);
    napi_set_named_property(env, maxScreenWantAgentInfo, MAX_SCREEN_WANT_AGENT_PKG, info);
    napi_create_string_utf8(env, (reminder.GetMaxScreenWantAgentInfo()->abilityName).c_str(), NAPI_AUTO_LENGTH, &info);
    napi_set_named_property(env, maxScreenWantAgentInfo, MAX_SCREEN_WANT_AGENT_ABILITY, info);
}

napi_value SetValidReminder(const napi_env &env, ReminderRequest &reminder, napi_value &result)
{
    ANSR_LOGD("called");
    napi_value value = nullptr;

    napi_create_string_utf8(env, reminder.Dump().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "reminder", value);

    // type
    ReminderRequest::ReminderType type = reminder.GetReminderType();
    napi_create_int32(env, static_cast<int32_t>(type), &value);
    napi_set_named_property(env, result, REMINDER_TYPE, value);

    // reminder
    ParseReminder(env, type, reminder, result);

    // title
    napi_create_string_utf8(env, reminder.GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, TITLE, value);

    // content
    napi_create_string_utf8(env, reminder.GetContent().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, CONTENT, value);

    // expiredContent
    napi_create_string_utf8(env, reminder.GetExpiredContent().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, EXPIRED_CONTENT, value);

    // snoozeContent
    napi_create_string_utf8(env, reminder.GetSnoozeContent().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, SNOOZE_CONTENT, value);

    // ringDuration
    napi_create_int64(env, reminder.GetRingDuration(), &value);
    napi_set_named_property(env, result, RING_DURATION, value);

    // timeInterval
    napi_create_int64(env, reminder.GetTimeInterval(), &value);
    napi_set_named_property(env, result, TIME_INTERVAL, value);

    // notificationId
    napi_create_int32(env, reminder.GetNotificationId(), &value);
    napi_set_named_property(env, result, NOTIFICATION_ID, value);

    // snoozeTimes
    napi_create_int32(env, reminder.GetSnoozeTimes(), &value);
    napi_set_named_property(env, result, SNOOZE_TIMES, value);

    // tapDismissed
    napi_get_boolean(env, reminder.IsTapDismissed(), &value);
    napi_set_named_property(env, result, TAPDISMISSED, value);

    // autoDeletedTime
    napi_create_int64(env, reminder.GetAutoDeletedTime(), &value);
    napi_set_named_property(env, result, AUTODELETEDTIME, value);

    // slotType
    NotificationNapi::SlotType jsSlotType;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(reminder.GetSlotType(), jsSlotType);
    napi_create_int32(env, static_cast<int32_t>(jsSlotType), &value);
    napi_set_named_property(env, result, SLOT_TYPE, value);

    // snoozeSlotType
    NotificationNapi::SlotType jsSnoozeSlotType;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(reminder.GetSnoozeSlotType(), jsSnoozeSlotType);
    napi_create_int32(env, static_cast<int32_t>(jsSnoozeSlotType), &value);
    napi_set_named_property(env, result, SNOOZE_SLOT_TYPE, value);

    // group id
    napi_create_string_utf8(env, reminder.GetGroupId().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, GROUP_ID, value);

    // custom ring uri
    napi_create_string_utf8(env, reminder.GetCustomRingUri().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, CUSTOM_RING_URI, value);

    // type
    ReminderRequest::RingChannel channel = reminder.GetRingChannel();
    napi_create_int32(env, static_cast<int32_t>(channel), &value);
    napi_set_named_property(env, result, RING_CHANNEL, value);

    // wantAgent
    ParseWantAgent(env, reminder, result);

    // maxScreenWantAgent
    ParseMaxScreenWantAgent(env, reminder, result);

    // actionButtons
    ParseActionButtons(env, reminder, result);

    return NotificationNapi::Common::NapiGetBoolean(env, true);
}

void GetValidRemindersInner(napi_env env, const std::vector<ReminderRequestAdaptation>& validReminders, napi_value& arr)
{
    int32_t count = 0;
    napi_create_array(env, &arr);
    for (auto& reminderRequestAdaptation : validReminders) {
        if (reminderRequestAdaptation.reminderRequest_ == nullptr) {
            ANSR_LOGW("null reminder");
            continue;
        }
        napi_value result = nullptr;
        napi_create_object(env, &result);
        if (!SetValidReminder(env, *reminderRequestAdaptation.reminderRequest_, result)) {
            ANSR_LOGW("Set reminder object failed");
            continue;
        }
        napi_set_element(env, arr, count, result);
        count++;
    }
    ANSR_LOGI("count = %{public}d", count);
}

void GetAllValidRemindersInner(napi_env env,
    const std::vector<ReminderRequestAdaptation>& validReminders, napi_value& arr)
{
    int32_t count = 0;
    napi_create_array(env, &arr);
    for (auto& reminderRequestAdaptation : validReminders) {
        napi_value result = nullptr;
        napi_create_object(env, &result);
        napi_value reminderReq = nullptr;
        napi_create_object(env, &reminderReq);
        napi_set_named_property(env, result, REMINDER_INFO_REMINDER_REQ, reminderReq);
        if (!SetValidReminder(env, *reminderRequestAdaptation.reminderRequest_, reminderReq)) {
            ANSR_LOGW("Set reminder object failed");
            continue;
        }
        napi_value reminderId = nullptr;
        napi_create_int32(env, reminderRequestAdaptation.reminderRequest_->GetReminderId(), &reminderId);
        napi_set_named_property(env, result, REMINDER_INFO_REMINDER_ID, reminderId);
        napi_set_element(env, arr, count, result);
        count++;
    }
    ANSR_LOGI("count = %{public}d", count);
}

napi_value InnerGetValidReminders(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseGetValidParameter(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), isThrow);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->isThrow = isThrow;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getValidReminders", NAPI_AUTO_LENGTH, &resourceName);

    // create and start async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("GetValid reminders napi_create_async_work start");
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::GetValidReminders(
                    asynccallbackinfo->validReminders);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            if (asynccallbackinfo) {
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    asynccallbackinfo->result = NotificationNapi::Common::NapiGetNull(env);
                } else {
                    GetValidRemindersInner(env, asynccallbackinfo->validReminders, asynccallbackinfo->result);
                }

                ReminderCommon::ReturnCallbackPromise(
                    env, asynccallbackinfo->info, asynccallbackinfo->result, asynccallbackinfo->isThrow);
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value InnerGetAllValidReminders(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    Parameters params;
    if (ParseGetValidParameter(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), isThrow);
    }

    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->isThrow = isThrow;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllValidReminders", NAPI_AUTO_LENGTH, &resourceName);
    
    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("GetAllValid reminders napi_create_async_work start");
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::GetValidReminders(
                    asynccallbackinfo->validReminders);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            if (asynccallbackinfo) {
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    asynccallbackinfo->result = NotificationNapi::Common::NapiGetNull(env);
                } else {
                    GetAllValidRemindersInner(env, asynccallbackinfo->validReminders, asynccallbackinfo->result);
                }
                
                ReminderCommon::ReturnCallbackPromise(
                    env, asynccallbackinfo->info, asynccallbackinfo->result, asynccallbackinfo->isThrow);
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetValidRemindersMgr(napi_env env, napi_callback_info info)
{
    return InnerGetValidReminders(env, info, true);
}

napi_value GetAllValidRemindersMgr(napi_env env, napi_callback_info info)
{
    return InnerGetAllValidReminders(env, info, true);
}

napi_value GetValidReminders(napi_env env, napi_callback_info info)
{
    return InnerGetValidReminders(env, info, false);
}

napi_value GetAllValidReminders(napi_env env, napi_callback_info info)
{
    return InnerGetAllValidReminders(env, info, false);
}

napi_value PublishReminderInner(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseParameters(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        napi_create_int32(env, -1, &(asynccallbackinfo->result));
        return DealErrorReturn(env, asynccallbackinfo->callback, asynccallbackinfo->result, isThrow);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminder = params.reminder;
    asynccallbackinfo->isThrow = isThrow;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "publishReminder", NAPI_AUTO_LENGTH, &resourceName);

    // create and start async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("Publish napi_create_async_work start");
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    ReminderHelper::PublishReminder(*(asynccallbackinfo->reminder), asynccallbackinfo->reminderId);
                ANSR_LOGD("Return reminderId=%{public}d", asynccallbackinfo->reminderId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("Publish napi_create_async_work complete start");
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            // reminderId
            if (asynccallbackinfo) {
                if (asynccallbackinfo->info.errorCode == ERR_OK) {
                    napi_create_int32(env, asynccallbackinfo->reminderId, &(asynccallbackinfo->result));
                } else {
                    napi_create_int32(env, -1, &(asynccallbackinfo->result));
                }

                ReminderCommon::ReturnCallbackPromise(
                    env, asynccallbackinfo->info, asynccallbackinfo->result, asynccallbackinfo->isThrow);
                ANSR_LOGI("Publish napi_create_async_work complete end");
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value PublishReminderMgr(napi_env env, napi_callback_info info)
{
    return PublishReminderInner(env, info, true);
}

napi_value PublishReminder(napi_env env, napi_callback_info info)
{
    return PublishReminderInner(env, info, false);
}

napi_value AddSlotInner(napi_env env, napi_callback_info info, bool isThrow)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseSlotParameters(env, info, params, *asynccallbackinfo, isThrow) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), isThrow);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->inType = params.inType;
    asynccallbackinfo->info.errorCode = params.errCode;
    asynccallbackinfo->isThrow = isThrow;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "AddSlot", NAPI_AUTO_LENGTH, &resourceName);

    // create and start async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("AddSlot napi_create_async_work start");
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo && (asynccallbackinfo->info.errorCode == ERR_OK)) {
                asynccallbackinfo->info.errorCode = NotificationHelper::AddSlotByType(asynccallbackinfo->inType);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfo *asynccallbackinfo = static_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };
                ReminderCommon::ReturnCallbackPromise(env, asynccallbackinfo->info,
                    NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
                ANSR_LOGD("AddSlot napi_create_async_work complete end.");
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    if (asynccallbackinfo->info.isCallback) {
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value AddSlotMgr(napi_env env, napi_callback_info info)
{
    return AddSlotInner(env, info, true);
}

napi_value AddSlot(napi_env env, napi_callback_info info)
{
    return AddSlotInner(env, info, false);
}

napi_value ParseAddExcludeDateParameter(const napi_env &env, const napi_callback_info &info, Parameters &params)
{
    ANSR_LOGD("called");
    size_t argc = ADD_EXCLUDE_DATE_PARAM_LEN;
    napi_value argv[ADD_EXCLUDE_DATE_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ADD_EXCLUDE_DATE_PARAM_LEN) {
        ANSR_LOGE("Wrong number of arguments");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }

    // argv[0]: reminder id
    int32_t reminderId = -1;
    if (!ReminderCommon::GetInt32(env, argv[0], nullptr, reminderId, true)) {
        ANSR_LOGE("Parse reminder id failed.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    if (reminderId < 0) {
        ANSR_LOGE("Param reminder id is illegal.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    params.reminderId = reminderId;

    // argv[1]: exclude date
    double date = 0.0;
    if (!ReminderCommon::GetDate(env, argv[1], nullptr, date)) {
        ANSR_LOGE("Parse exclude date failed.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    if (date < 0.0) {
        ANSR_LOGE("Param exclude date is illegal.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    params.excludeDate = static_cast<int64_t>(date);
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value AddExcludeDate(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseAddExcludeDateParameter(env, info, params) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), true);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->excludeDate = params.excludeDate;
    asynccallbackinfo->isThrow = true;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "addExcludeDate", NAPI_AUTO_LENGTH, &resourceName);

    bool isCallback = asynccallbackinfo->info.isCallback;

    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("AddExcludeDate napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::AddExcludeDate(asynccallbackinfo->reminderId,
                    asynccallbackinfo->excludeDate);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("AddExcludeDate napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGI("AddExcludeDate napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    return isCallback ? NotificationNapi::Common::NapiGetNull(env) : promise;
}

napi_value ParseReminderIdParameter(const napi_env &env, const napi_callback_info &info, Parameters &params)
{
    ANSR_LOGD("called");
    size_t argc = DEL_EXCLUDE_DATE_PARAM_LEN;
    napi_value argv[DEL_EXCLUDE_DATE_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < DEL_EXCLUDE_DATE_PARAM_LEN) {
        ANSR_LOGE("Wrong number of arguments");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }

    // argv[0]: reminder id
    int32_t reminderId = -1;
    if (!ReminderCommon::GetInt32(env, argv[0], nullptr, reminderId, true)) {
        ANSR_LOGE("Parse reminder id failed.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    if (reminderId < 0) {
        ANSR_LOGE("Param reminder id is illegal.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_INVALID_PARAM);
        return nullptr;
    }
    params.reminderId = reminderId;
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value DelExcludeDates(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");

    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseReminderIdParameter(env, info, params) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), true);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->isThrow = true;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "deleteExcludeDates", NAPI_AUTO_LENGTH, &resourceName);

    bool isCallback = asynccallbackinfo->info.isCallback;

    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("DelExcludeDates napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::DelExcludeDates(asynccallbackinfo->reminderId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("DelExcludeDates napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGI("DelExcludeDates napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    return isCallback ? NotificationNapi::Common::NapiGetNull(env) : promise;
}

void GetExcludeDatesInner(napi_env env, const std::vector<int64_t>& dates, napi_value& arr)
{
    int32_t count = 0;
    napi_create_array(env, &arr);
    for (auto date : dates) {
        napi_value result = nullptr;
        napi_create_date(env, static_cast<double>(date), &result);
        napi_set_element(env, arr, count, result);
        count++;
    }
    ANSR_LOGI("count = %{public}d", count);
}

napi_value GetExcludeDates(napi_env env, napi_callback_info info)
{
    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseReminderIdParameter(env, info, params) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), true);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->isThrow = true;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getExcludeDates", NAPI_AUTO_LENGTH, &resourceName);
    
    bool isCallback = asynccallbackinfo->info.isCallback;

    // create and queue async work
    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("GetExcludeDates napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::GetExcludeDates(asynccallbackinfo->reminderId,
                    asynccallbackinfo->excludeDates);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("GetExcludeDates napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            if (asynccallbackinfo) {
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    asynccallbackinfo->result = NotificationNapi::Common::NapiGetNull(env);
                } else {
                    GetExcludeDatesInner(env, asynccallbackinfo->excludeDates, asynccallbackinfo->result);
                }
                
                ReminderCommon::ReturnCallbackPromise(
                    env, asynccallbackinfo->info, asynccallbackinfo->result, asynccallbackinfo->isThrow);
            }
            ANSR_LOGI("GetExcludeDates napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    return isCallback ? NotificationNapi::Common::NapiGetNull(env) : promise;
}

napi_value ParseUpdateReminderParameter(const napi_env &env, const napi_callback_info &info, Parameters &params)
{
    ANSR_LOGD("called");
    size_t argc = UPDATE_REMINDER_PARAM_LEN;
    napi_value argv[UPDATE_REMINDER_PARAM_LEN] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < UPDATE_REMINDER_PARAM_LEN) {
        ANSR_LOGE("Wrong number of arguments");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }

    // argv[0]: reminder id
    int32_t reminderId = -1;
    if (!ReminderCommon::GetInt32(env, argv[0], nullptr, reminderId, true)) {
        ANSR_LOGE("Parse reminder id failed.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }
    if (reminderId < 0) {
        ANSR_LOGE("Param reminder id is illegal.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }
    if (ReminderCommon::GetReminderRequest(env, argv[1], params.reminder) == nullptr) {
        ANSR_LOGE("UpdateReminder returns nullptr");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }
    params.reminderId = reminderId;
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value UpdateReminder(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");
    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

    // param
    Parameters params;
    if (ParseUpdateReminderParameter(env, info, params) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), true);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->reminder = params.reminder;
    asynccallbackinfo->isThrow = true;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "updateReminder", NAPI_AUTO_LENGTH, &resourceName);

    bool isCallback = asynccallbackinfo->info.isCallback;
    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("UpdateReminder napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = ReminderHelper::UpdateReminder(asynccallbackinfo->reminderId,
                    *(asynccallbackinfo->reminder));
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("UpdateReminder napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGI("UpdateReminder napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();

    return isCallback ? NotificationNapi::Common::NapiGetNull(env) : promise;
}

napi_value CancelReminderOnDisplay(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");
    AsyncCallbackInfo *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfo(env);
    if (!asynccallbackinfo) {
        ANSR_LOGE("Low memory.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };
    // param
    Parameters params;
    if (ParseCanCelParameter(env, info, params, *asynccallbackinfo, true) == nullptr) {
        return DealErrorReturn(env, asynccallbackinfo->callback, NotificationNapi::Common::NapiGetNull(env), true);
    }

    // promise
    napi_value promise = nullptr;
    SetAsynccallbackinfo(env, *asynccallbackinfo, promise);
    asynccallbackinfo->reminderId = params.reminderId;
    asynccallbackinfo->isThrow = true;

    // resource name
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelReminderOnDisplay", NAPI_AUTO_LENGTH, &resourceName);

    bool isCallback = asynccallbackinfo->info.isCallback;
    // create and queue async work
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANSR_LOGI("CancelReminderOnDisplay napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    ReminderHelper::CancelReminderOnDisplay(asynccallbackinfo->reminderId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANSR_LOGI("CancelReminderOnDisplay napi_create_async_work complete start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfo *>(data);
            std::unique_ptr<AsyncCallbackInfo> callbackPtr { asynccallbackinfo };

            ReminderCommon::ReturnCallbackPromise(
                env, asynccallbackinfo->info, NotificationNapi::Common::NapiGetNull(env), asynccallbackinfo->isThrow);
            ANSR_LOGI("CancelReminderOnDisplay napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));
    callbackPtr.release();
    return isCallback ? NotificationNapi::Common::NapiGetNull(env) : promise;
}

napi_value SubscribeReminderState(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");
    return JsReminderStateListener::GetInstance().RegisterReminderStateCallback(env, info);
}

napi_value UnSubscribeReminderState(napi_env env, napi_callback_info info)
{
    ANSR_LOGD("called");
    return JsReminderStateListener::GetInstance().UnRegisterReminderStateCallback(env, info);
}
}
}
