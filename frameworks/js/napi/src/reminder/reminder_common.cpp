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

#include "reminder/reminder_common.h"

#include "ans_log_wrapper.h"
#include "common.h"
#include "napi_common.h"
#include "ipc_skeleton.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "tokenid_kit.h"
#include "securec.h"

namespace OHOS {
namespace ReminderAgentNapi {
using namespace OHOS::Notification;
const uint32_t ASYNC_CALLBACK_PARAM_NUM = 2;

napi_value ReminderCommon::GetReminderRequest(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_object) {
        ANSR_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    // gen reminder
    if (GenReminder(env, value, reminder) == nullptr) {
        return nullptr;
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

bool ReminderCommon::GenActionButtons(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder, bool isSysApp)
{
    char str[NotificationNapi::STR_MAX_SIZE] = {0};
    napi_valuetype valuetype = napi_undefined;
    napi_value actionButtons = nullptr;
    if (!GetObject(env, value, ReminderAgentNapi::ACTION_BUTTON, actionButtons)) {
        return true;
    }
    bool isArray = false;
    napi_is_array(env, actionButtons, &isArray);
    if (!isArray) {
        ANSR_LOGE("Wrong argument type:%{public}s. array expected.", ACTION_BUTTON);
        return false;
    }

    uint32_t length = 0;
    napi_get_array_length(env, actionButtons, &length);
    for (size_t i = 0; i < length; i++) {
        napi_value actionButton = nullptr;
        napi_get_element(env, actionButtons, i, &actionButton);
        NAPI_CALL_BASE(env, napi_typeof(env, actionButton, &valuetype), false);
        if (valuetype != napi_object) {
            ANSR_LOGE("Wrong element type:%{public}s. object expected.", ACTION_BUTTON);
            return false;
        }

        int32_t buttonType = static_cast<int32_t>(ReminderRequest::ActionButtonType::INVALID);
        if (GetStringUtf8(env, actionButton,
            ReminderAgentNapi::ACTION_BUTTON_TITLE, str, NotificationNapi::STR_MAX_SIZE) &&
            GetInt32(env, actionButton, ReminderAgentNapi::ACTION_BUTTON_TYPE, buttonType, false)) {
            if (!(ReminderRequest::ActionButtonType(buttonType) == ReminderRequest::ActionButtonType::CLOSE ||
                ReminderRequest::ActionButtonType(buttonType) == ReminderRequest::ActionButtonType::SNOOZE ||
                (ReminderRequest::ActionButtonType(buttonType) == ReminderRequest::ActionButtonType::CUSTOM &&
                isSysApp))) {
                ANSR_LOGE("Wrong argument type:%{public}s. buttonType not support.", ACTION_BUTTON);
                return false;
            }
            HandleActionButtonTitle(env, actionButton, reminder, str, buttonType);
        } else {
            ANSR_LOGE("Parse action button error.");
            return false;
        }
    }
    return true;
}

bool ReminderCommon::GenRingChannel(const napi_env& env, const napi_value& value,
    std::shared_ptr<ReminderRequest>& reminder)
{
    int32_t ringChannel = static_cast<int32_t>(ReminderRequest::RingChannel::ALARM);
    if (GetInt32(env, value, ReminderAgentNapi::RING_CHANNEL, ringChannel, false)) {
        if (!(ReminderRequest::RingChannel(ringChannel) == ReminderRequest::RingChannel::ALARM ||
            ReminderRequest::RingChannel(ringChannel) == ReminderRequest::RingChannel::MEDIA)) {
            ANSR_LOGE("Wrong argument type:%{public}s. ringChannel not support.", RING_CHANNEL);
            return false;
        }
        reminder->SetRingChannel(static_cast<ReminderRequest::RingChannel>(ringChannel));
    }
    return true;
}

void ReminderCommon::HandleActionButtonTitle(const napi_env &env, const napi_value &actionButton,
    std::shared_ptr<ReminderRequest>& reminder, const char* str, int32_t buttonType)
{
    char res[NotificationNapi::STR_MAX_SIZE] = {0};
    std::string resource = "";
    if (GetStringUtf8(env, actionButton, ReminderAgentNapi::ACTION_BUTTON_RESOURCE, res,
        NotificationNapi::STR_MAX_SIZE)) {
        resource = std::string(res);
    }

    std::string title(str);
    auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    if (ReminderRequest::ActionButtonType(buttonType) == ReminderRequest::ActionButtonType::CUSTOM) {
        GetButtonWantAgent(env, actionButton, reminder, buttonWantAgent);
    }
    // gen buttonDataShareUpdate
    auto buttonDataShareUpdate = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    if (ReminderRequest::ActionButtonType(buttonType) != ReminderRequest::ActionButtonType::INVALID) {
        GetButtonDataShareUpdate(env, actionButton, buttonDataShareUpdate);
    }
    reminder->SetActionButton(title, static_cast<ReminderRequest::ActionButtonType>(buttonType),
        resource, buttonWantAgent, buttonDataShareUpdate);
    ANSR_LOGD("button title=%{public}s, type=%{public}d, resource=%{public}s",
        title.c_str(), buttonType, resource.c_str());
}

bool ReminderCommon::IsSelfSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        ANSR_LOGE("This application is not system-app, can not use system-api");
        return false;
    }
    return true;
}

void ReminderCommon::GetButtonWantAgent(const napi_env &env, const napi_value &value,
    std::shared_ptr<ReminderRequest>& reminder, std::shared_ptr<ReminderRequest::ButtonWantAgent>& buttonWantAgent)
{
    char str[NotificationNapi::STR_MAX_SIZE] = {0};
    napi_value wantAgent = nullptr;
    if (GetObject(env, value, ReminderAgentNapi::BUTTON_WANT_AGENT, wantAgent)) {
        if (GetStringUtf8(env, wantAgent,
            ReminderAgentNapi::BUTTON_WANT_AGENT_PKG, str, NotificationNapi::STR_MAX_SIZE)) {
            buttonWantAgent->pkgName = str;
        }
        if (GetStringUtf8(env, wantAgent,
            ReminderAgentNapi::BUTTON_WANT_AGENT_ABILITY, str, NotificationNapi::STR_MAX_SIZE)) {
            buttonWantAgent->abilityName = str;
        }
        if (GetStringUtf8(env, wantAgent,
            ReminderAgentNapi::BUTTON_WANT_AGENT_URI, str, NotificationNapi::STR_MAX_SIZE)) {
            reminder->SetCustomButtonUri(str);
        }
    }
}

// uri:string  equalTo{key:value}  valuesBucket{key:value}
void ReminderCommon::GetButtonDataShareUpdate(const napi_env &env, const napi_value &value,
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate>& buttonDataShareUpdate)
{
    napi_value dataShare = nullptr;
    if (GetObject(env, value, BUTTON_DATA_SHARE_UPDATE, dataShare)) {
        // dataShare uri
        char str[NotificationNapi::STR_MAX_SIZE] = {0};
        if (GetStringUtf8(env, dataShare, BUTTON_DATA_SHARE_UPDATE_URI, str, NotificationNapi::STR_MAX_SIZE)) {
            ANSR_LOGD("gen dataShareUri success");
            buttonDataShareUpdate->uri = str;
        }
        // dataShare equalTo
        napi_value equalTo = nullptr;
        std::string valueBucketString;
        if (GetObject(env, dataShare, BUTTON_DATA_SHARE_UPDATE_EQUALTO, equalTo)) {
            if (GetValueBucketObject(valueBucketString, env, equalTo)) {
                ANSR_LOGD("gen dataShareEqualTo success");
                buttonDataShareUpdate->equalTo = valueBucketString;
            }
        }
        // dataShare valuesBucket
        napi_value valuesBucket = nullptr;
        valueBucketString.clear();
        if (GetObject(env, dataShare, BUTTON_DATA_SHARE_UPDATE_VALUE, valuesBucket)) {
            if (GetValueBucketObject(valueBucketString, env, valuesBucket)) {
                ANSR_LOGD("gen dataShareValuesBucket success");
                buttonDataShareUpdate->valuesBucket = valueBucketString;
            }
        }
    }
}

// get {key:value} to string(key:type:value)
bool ReminderCommon::GetValueBucketObject(std::string &valueBucketString, const napi_env &env, const napi_value &arg)
{
    // arrary
    napi_value keys = 0;
    napi_get_property_names(env, arg, &keys);
    uint32_t arrlen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrlen);
    if (status != napi_ok) {
        ANSR_LOGE("get the valuesBucket length err");
        return false;
    }
    for (size_t i = 0; i < arrlen; ++i) {
        // key
        napi_value key = 0;
        status = napi_get_element(env, keys, i, &key);
        if (status != napi_ok) {
            ANSR_LOGW("get valuesBucket err");
            continue;
        }
        std::string keyStr = GetStringFromJS(env, key);
        if (!ValidateString(keyStr)) {
            ANSR_LOGE("The key contains separator");
            return false;
        }
        // value
        napi_value value = 0;
        napi_get_property(env, arg, key, &value);
        bool ret;
        std::string type;
        std::string valueObject = Convert2Value(env, value, ret, type);
        if (!ret) {
            ANSR_LOGW("parse valuesBucket err");
            continue;
        }
        if (!ValidateString(valueObject)) {
            ANSR_LOGE("The value contains separator");
            return false;
        }
        valueBucketString += keyStr + ReminderRequest::SEP_BUTTON_VALUE + type
            + ReminderRequest::SEP_BUTTON_VALUE + valueObject;
        if (i < arrlen - 1) {
            valueBucketString += ReminderRequest::SEP_BUTTON_VALUE_TYPE;
        }
    }
    return true;
}

// get string
std::string ReminderCommon::GetStringFromJS(const napi_env &env, const napi_value &param,
    const std::string &defaultValue)
{
    size_t size = 0;
    if (napi_get_value_string_utf8(env, param, nullptr, 0, &size) != napi_ok) {
        return defaultValue;
    }
    if (size == 0) {
        return defaultValue;
    }

    char *buf = new (std::nothrow) char[size + 1];
    std::string value("");
    if (buf == nullptr) {
        return value;
    }
    (void)memset_s(buf, size + 1, 0, size + 1);
    bool rev = napi_get_value_string_utf8(env, param, buf, size + 1, &size) == napi_ok;
    if (rev) {
        value = buf;
    } else {
        value = defaultValue;
    }

    if (buf != nullptr) {
        delete[] buf;
        buf = nullptr;
    }
    return value;
}

// get type and value
std::string ReminderCommon::Convert2Value(const napi_env &env, const napi_value &value, bool &status, std::string &type)
{
    // array type
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    status = true;
    // gen value
    std::string valueString;
    std::vector<uint8_t> valueBlob;
    switch (valueType) {
        case napi_null: {
            type = "null";
            valueString = type;
            break;
        }
        case napi_boolean: {
            type = "bool";
            bool valueBool = false;
            napi_get_value_bool(env, value, &valueBool);
            valueString = std::to_string(valueBool);
            break;
        }
        case napi_number: {
            type = "double";
            double valueNumber = 0;
            napi_get_value_double(env, value, &valueNumber);
            valueString = std::to_string(valueNumber);
            break;
        }
        case napi_string: {
            type = "string";
            valueString = GetStringFromJS(env, value);
            break;
        }
        case napi_object: {
            type = "vector";
            valueBlob = Convert2U8Vector(env, value);
            for (auto it = valueBlob.begin(); it != valueBlob.end(); ++it) {
                valueString += std::to_string(*it);
                if ((it + 1) != valueBlob.end()) {
                    valueString += ReminderRequest::SEP_BUTTON_VALUE_BLOB;
                }
            }
            break;
        }
        default: {
            ANSR_LOGE("Convert2Value err");
            status = false;
            break;
        }
    }
    return valueString;
}

// get vector<uint8_t>
std::vector<uint8_t> ReminderCommon::Convert2U8Vector(const napi_env &env, const napi_value &input_array)
{
    bool isTypedArray = false;
    bool isArrayBuffer = false;
    // type is array?
    napi_is_typedarray(env, input_array, &isTypedArray);
    if (!isTypedArray) {
        // buffer whether or not it exists?
        napi_is_arraybuffer(env, input_array, &isArrayBuffer);
        if (!isArrayBuffer) {
            ANSR_LOGE("unknow type");
            return {};
        }
    }
    size_t length = 0;
    void *data = nullptr;
    // get array
    if (isTypedArray) {
        napi_typedarray_type type;
        napi_value input_buffer = nullptr;
        size_t byte_offset = 0;
        napi_get_typedarray_info(env, input_array, &type, &length, &data, &input_buffer, &byte_offset);
        if (type != napi_uint8_array || data == nullptr) {
            ANSR_LOGW("napi_get_typedarray_info err");
            return {};
        }
    } else {
        napi_get_arraybuffer_info(env, input_array, &data, &length);
        if (data == nullptr || length == 0) {
            ANSR_LOGW("napi_get_arraybuffer_info err");
            return {};
        }
    }
    return std::vector<uint8_t>((uint8_t *)data, ((uint8_t *)data) + length);
}

bool ReminderCommon::ValidateString(const std::string &str)
{
    if (str.find(ReminderRequest::SEP_BUTTON_VALUE_TYPE) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE_TYPE");
        return false;
    }
    if (str.find(ReminderRequest::SEP_BUTTON_VALUE) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE");
        return false;
    }
    if (str.find(ReminderRequest::SEP_BUTTON_VALUE_BLOB) != std::string::npos) {
        ANSR_LOGW("The string contains SEP_BUTTON_VALUE_BLOB");
        return false;
    }
    return true;
}

bool ReminderCommon::GenWantAgent(
    const napi_env &env, const napi_value &value, const char* name,
    std::shared_ptr<ReminderRequest::WantAgentInfo>& wantAgentInfo)
{
    char str[NotificationNapi::STR_MAX_SIZE] = {0};
    napi_value wantAgent = nullptr;
    if (GetObject(env, value, name, wantAgent)) {
        wantAgentInfo = std::make_shared<ReminderRequest::WantAgentInfo>();
        if (GetStringUtf8(env, wantAgent, ReminderAgentNapi::WANT_AGENT_PKG, str, NotificationNapi::STR_MAX_SIZE)) {
            wantAgentInfo->pkgName = str;
        }
        if (GetStringUtf8(env, wantAgent,
            ReminderAgentNapi::WANT_AGENT_ABILITY, str, NotificationNapi::STR_MAX_SIZE)) {
            wantAgentInfo->abilityName = str;
        }
        if (GetStringUtf8(env, wantAgent,
            ReminderAgentNapi::WANT_AGENT_URI, str, NotificationNapi::STR_MAX_SIZE)) {
            wantAgentInfo->uri = str;
        }
        napi_value params = nullptr;
        if (GetObject(env, wantAgent, ReminderAgentNapi::WANT_AGENT_PARAMETERS, params)) {
            AAFwk::WantParams wantParams;
            if (AppExecFwk::UnwrapWantParams(env, params, wantParams)) {
                wantAgentInfo->parameters = wantParams;
            }
        }
    }
    return true;
}

void ReminderCommon::GenMaxScreenWantAgent(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    char str[NotificationNapi::STR_MAX_SIZE] = {0};
    napi_value maxScreenWantAgent = nullptr;
    if (GetObject(env, value, ReminderAgentNapi::MAX_SCREEN_WANT_AGENT, maxScreenWantAgent)) {
        auto maxScreenWantAgentInfo = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
        if (GetStringUtf8(env, maxScreenWantAgent,
            ReminderAgentNapi::MAX_SCREEN_WANT_AGENT_PKG, str, NotificationNapi::STR_MAX_SIZE)) {
            maxScreenWantAgentInfo->pkgName = str;
        }
        if (GetStringUtf8(env, maxScreenWantAgent,
            ReminderAgentNapi::MAX_SCREEN_WANT_AGENT_ABILITY, str, NotificationNapi::STR_MAX_SIZE)) {
            maxScreenWantAgentInfo->abilityName = str;
        }
        reminder->SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
    }
}
bool ReminderCommon::CreateReminder(
    const napi_env &env, const napi_value &value, const bool isSysApp, std::shared_ptr<ReminderRequest>& reminder)
{
    napi_value result = nullptr;
    napi_get_named_property(env, value, ReminderAgentNapi::REMINDER_TYPE, &result);
    int32_t reminderType = -1;
    napi_get_value_int32(env, result, &reminderType);
    switch (ReminderRequest::ReminderType(reminderType)) {
        case ReminderRequest::ReminderType::TIMER:
            CreateReminderTimer(env, value, reminder);
            break;
        case ReminderRequest::ReminderType::ALARM:
            CreateReminderAlarm(env, value, reminder);
            break;
        case ReminderRequest::ReminderType::CALENDAR:
            CreateReminderCalendar(env, value, isSysApp, reminder);
            break;
        default:
            ANSR_LOGE("Reminder type is not support. (type:%{public}d)", reminderType);
            break;
    }
    if (reminder == nullptr) {
        ANSR_LOGE("Instance of reminder error.");
        return false;
    }
    return true;
}

napi_value ReminderCommon::GenReminder(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    // reminderType
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, ReminderAgentNapi::REMINDER_TYPE, &hasProperty));
    if (!hasProperty) {
        ANSR_LOGE("Property %{public}s expected.", ReminderAgentNapi::REMINDER_TYPE);
        return nullptr;
    }

    // createReminder
    bool isSysApp = IsSelfSystemApp();
    if (!CreateReminder(env, value, isSysApp, reminder)) {
        return nullptr;
    }
    reminder->SetSystemApp(isSysApp);
    GenReminderStringInner(env, value, reminder);
    if (!GenReminderIntInner(env, value, reminder)) {
        return nullptr;
    }
    GenReminderBoolInner(env, value, reminder);

    // snoozeSlotType
    int32_t snoozeSlotType = 0;
    if (GetInt32(env, value, ReminderAgentNapi::SNOOZE_SLOT_TYPE, snoozeSlotType, false)) {
        enum NotificationConstant::SlotType actureSnoozeType = NotificationConstant::SlotType::OTHER;
        if (!NotificationNapi::AnsEnumUtil::SlotTypeJSToC(
            NotificationNapi::SlotType(snoozeSlotType), actureSnoozeType)) {
            ANSR_LOGW("snooze slot type not support.");
            return nullptr;
        }
        reminder->SetSnoozeSlotType(actureSnoozeType);
    }

    // wantAgent
    std::shared_ptr<ReminderRequest::WantAgentInfo> wantAgentInfo;
    if (!GenWantAgent(env, value, ReminderAgentNapi::WANT_AGENT, wantAgentInfo)) {
        return nullptr;
    }
    reminder->SetWantAgentInfo(wantAgentInfo);

    // maxScreenWantAgent
    GenMaxScreenWantAgent(env, value, reminder);

    // actionButtons
    if (!GenActionButtons(env, value, reminder, isSysApp)) {
        return nullptr;
    }

    // ringChannel
    if (!GenRingChannel(env, value, reminder)) {
        return nullptr;
    }

    return NotificationNapi::Common::NapiGetNull(env);
}

void ReminderCommon::GenReminderStringInner(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    char str[NotificationNapi::STR_MAX_SIZE] = {0};

    // title
    if (GetStringUtf8(env, value, ReminderAgentNapi::TITLE, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetTitle(std::string(str));
    }

    // content
    if (GetStringUtf8(env, value, ReminderAgentNapi::CONTENT, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetContent(std::string(str));
    }

    // expiredContent
    if (GetStringUtf8(env, value, ReminderAgentNapi::EXPIRED_CONTENT, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetExpiredContent(std::string(str));
    }

    // snoozeContent
    if (GetStringUtf8(env, value, ReminderAgentNapi::SNOOZE_CONTENT, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetSnoozeContent(std::string(str));
    }

    // group id
    if (GetStringUtf8(env, value, ReminderAgentNapi::GROUP_ID, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetGroupId(std::string(str));
    }

    // custom ring uri
    if (GetStringUtf8(env, value, ReminderAgentNapi::CUSTOM_RING_URI, str, NotificationNapi::STR_MAX_SIZE)) {
        reminder->SetCustomRingUri(std::string(str));
    }
}

bool ReminderCommon::GenReminderIntInner(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    // ringDuration
    int64_t propVal = 0;
    if (GetInt64(env, value, ReminderAgentNapi::RING_DURATION, propVal)) {
        if (propVal < 0 || propVal > static_cast<int64_t>(
            ReminderRequest::MAX_RING_DURATION / ReminderRequest::MILLI_SECONDS)) {
            ANSR_LOGE("ring duration value is error!");
            return false;
        }
        uint64_t ringDuration = static_cast<uint64_t>(propVal);
        reminder->SetRingDuration(ringDuration);
    }

    // timeInterval
    if (GetInt64(env, value, ReminderAgentNapi::TIME_INTERVAL, propVal)) {
        if (propVal < 0) {
            reminder->SetTimeInterval(0);
        } else {
            uint64_t timeInterval = static_cast<uint64_t>(propVal);
            reminder->SetTimeInterval(timeInterval);
        }
    }

    // notificationId
    int32_t propertyVal = 0;
    if (GetInt32(env, value, ReminderAgentNapi::NOTIFICATION_ID, propertyVal, false)) {
        reminder->SetNotificationId(propertyVal);
    }

    // snoozeTimes
    if (GetInt32(env, value, ReminderAgentNapi::SNOOZE_TIMES, propertyVal, false)) {
        if (propertyVal < 0) {
            reminder->SetSnoozeTimes(0);
        } else {
            uint8_t snoozeTimes = propertyVal > UINT8_MAX ? UINT8_MAX : static_cast<uint8_t>(propertyVal);
            reminder->SetSnoozeTimes(static_cast<uint8_t>(snoozeTimes));
        }
    }

    // slotType
    int32_t slotType = 0;
    if (GetInt32(env, value, ReminderAgentNapi::SLOT_TYPE, slotType, false)) {
        enum NotificationConstant::SlotType actureType = NotificationConstant::SlotType::OTHER;
        if (!NotificationNapi::AnsEnumUtil::SlotTypeJSToC(NotificationNapi::SlotType(slotType), actureType)) {
            ANSR_LOGE("slot type not support.");
            return false;
        }
        reminder->SetSlotType(actureType);
    } else if (!reminder->IsSystemApp()) {
        reminder->SetSlotType(NotificationConstant::SlotType::OTHER);
    }

    //autoDeletedTime
    int64_t autoDeletedTime = 0;
    if (GetInt64(env, value, ReminderAgentNapi::AUTODELETEDTIME, autoDeletedTime)) {
        if (autoDeletedTime > 0) {
            reminder->SetAutoDeletedTime(autoDeletedTime);
        }
    }
    return GenReminderIntInnerOther(env, value, reminder);
}

bool ReminderCommon::GenReminderIntInnerOther(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    int32_t resourceId = 0;
    // title
    if (GetInt32(env, value, ReminderAgentNapi::TITLE_RESOURCE_ID, resourceId, false)) {
        reminder->SetTitleResourceId(resourceId);
    }

    // content
    if (GetInt32(env, value, ReminderAgentNapi::CONTENT_RESOURCE_ID, resourceId, false)) {
        reminder->SetContentResourceId(resourceId);
    }

    // expiredContent
    if (GetInt32(env, value, ReminderAgentNapi::EXPIRED_CONTENT_RESOURCE_ID, resourceId, false)) {
        reminder->SetExpiredContentResourceId(resourceId);
    }

    // snoozeContent
    if (GetInt32(env, value, ReminderAgentNapi::SNOOZE_CONTENT_RESOURCE_ID, resourceId, false)) {
        reminder->SetSnoozeContentResourceId(resourceId);
    }
    return true;
}

void ReminderCommon::GenReminderBoolInner(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    // tapDismissed
    bool tapDismissed = false;
    if (GetBool(env, value, ReminderAgentNapi::TAPDISMISSED, tapDismissed)) {
        reminder->SetTapDismissed(tapDismissed);
    }
}

bool ReminderCommon::GetStringUtf8(const napi_env &env, const napi_value &value,
    const char* propertyName, char* propertyVal, const int32_t size)
{
    bool hasProperty = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    size_t strLen = 0;

    NAPI_CALL_BASE(env, napi_has_named_property(env, value, propertyName, &hasProperty), false);
    if (hasProperty) {
        napi_get_named_property(env, value, propertyName, &result);
        NAPI_CALL_BASE(env, napi_typeof(env, result, &valuetype), false);
        if (valuetype != napi_string) {
            ANSR_LOGE("Wrong argument type:%{public}s. string expected.", propertyName);
            return false;
        }
        NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, result, propertyVal, size - 1, &strLen), false);
    }
    return hasProperty;
}

bool ReminderCommon::GetBool(const napi_env &env, const napi_value &value,
    const char* propertyName, bool& propertyVal)
{
    bool hasProperty = false;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_has_named_property(env, value, propertyName, &hasProperty), false);
    if (!hasProperty) {
        ANSR_LOGE("Does not have argument type:%{public}s.", propertyName);
        return false;
    }
    napi_get_named_property(env, value, propertyName, &result);
    NAPI_CALL_BASE(env, napi_typeof(env, result, &valuetype), false);
    if (valuetype != napi_boolean) {
        ANSR_LOGE("Wrong argument type:%{public}s. boolean expected.", propertyName);
        return false;
    }
    napi_get_value_bool(env, result, &propertyVal);
    return true;
}

bool ReminderCommon::GetInt32(const napi_env &env, const napi_value &value,
    const char* propertyName, int32_t& propertyVal, bool isNecessary)
{
    napi_value result = nullptr;
    if (!GetPropertyValIfExist(env, value, propertyName, result)) {
        if (isNecessary) {
            ANSR_LOGW("Correct property %{public}s expected.", propertyName);
        }
        return false;
    }
    napi_get_value_int32(env, result, &propertyVal);
    return true;
}

bool ReminderCommon::GetInt64(const napi_env &env, const napi_value &value,
    const char* propertyName, int64_t& propertyVal)
{
    napi_value result = nullptr;
    if (!GetPropertyValIfExist(env, value, propertyName, result)) {
        return false;
    }
    napi_get_value_int64(env, result, &propertyVal);
    return true;
}

bool ReminderCommon::GetPropertyValIfExist(const napi_env &env, const napi_value &value,
    const char* propertyName, napi_value& propertyVal)
{
    napi_valuetype valuetype = napi_undefined;
    if (propertyName == nullptr) {
        propertyVal = value;
    } else {
        bool hasProperty = false;
        napi_status status = napi_has_named_property(env, value, propertyName, &hasProperty);
        if (status != napi_ok || !hasProperty) {
            return false;
        }
        napi_get_named_property(env, value, propertyName, &propertyVal);
    }
    napi_status status = napi_typeof(env, propertyVal, &valuetype);
    if (status != napi_ok || valuetype != napi_number) {
        if (propertyName == nullptr) {
            ANSR_LOGW("Wrong argument type. number expected.");
        } else {
            ANSR_LOGW("Wrong argument type:%{public}s, number expected.", propertyName);
        }
        return false;
    }
    return true;
}

bool ReminderCommon::GetObject(const napi_env &env, const napi_value &value,
    const char* propertyName, napi_value& propertyVal)
{
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;

    NAPI_CALL_BASE(env, napi_has_named_property(env, value, propertyName, &hasProperty), false);
    if (!hasProperty) {
        return false;
    }
    napi_get_named_property(env, value, propertyName, &propertyVal);
    NAPI_CALL_BASE(env, napi_typeof(env, propertyVal, &valuetype), false);
    if (valuetype != napi_object) {
        ANSR_LOGE("Wrong argument type:%{public}s. object expected.", propertyName);
        return false;
    }
    return true;
}

bool ReminderCommon::GetDate(const napi_env& env, const napi_value& value,
    const char* propertyName, double& date)
{
    napi_value propertyValue = nullptr;
    if (propertyName == nullptr) {
        propertyValue = value;
    } else {
        bool hasProperty = false;
        NAPI_CALL_BASE(env, napi_has_named_property(env, value, propertyName, &hasProperty), false);
        if (!hasProperty) {
            ANSR_LOGE("");
            return false;
        }
        napi_get_named_property(env, value, propertyName, &propertyValue);
    }
    bool isDate = false;
    napi_is_date(env, propertyValue, &isDate);
    if (!isDate) {
        ANSR_LOGE("Wrong argument type. Date expected.");
        return false;
    }
    napi_get_date_value(env, propertyValue, &date);
    return true;
}

napi_value ReminderCommon::CreateReminderTimer(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    int64_t propertyCountDownTime = 0;
    if (!GetInt64(env, value, ReminderAgentNapi::TIMER_COUNT_DOWN_TIME, propertyCountDownTime)) {
        ANSR_LOGW("Correct property %{public}s expected.", ReminderAgentNapi::TIMER_COUNT_DOWN_TIME);
        return nullptr;
    }

    auto countDownTimeInSeconds = static_cast<uint64_t>(propertyCountDownTime);
    if (propertyCountDownTime <= 0 || countDownTimeInSeconds >= (UINT64_MAX / ReminderRequest::MILLI_SECONDS)) {
        ANSR_LOGE("Create countDown reminder fail: designated %{public}s is illegal.",
            ReminderAgentNapi::TIMER_COUNT_DOWN_TIME);
        return nullptr;
    }

    reminder = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ReminderCommon::CreateReminderAlarm(
    const napi_env &env, const napi_value &value, std::shared_ptr<ReminderRequest>& reminder)
{
    // hour
    int32_t propertyHourVal = 0;
    const int32_t maxHour = 23;
    if (!GetInt32(env, value, ReminderAgentNapi::ALARM_HOUR, propertyHourVal, true)) {
        return nullptr;
    }

    // minute
    int32_t propertyMinuteVal = 0;
    const int32_t maxMinute = 59;
    if (!GetInt32(env, value, ReminderAgentNapi::ALARM_MINUTE, propertyMinuteVal, true)) {
        return nullptr;
    }

    if ((propertyHourVal < 0) || (propertyHourVal > maxHour)) {
        ANSR_LOGE("Create alarm reminder fail: designated %{public}s must between [0, 23].",
            ReminderAgentNapi::ALARM_HOUR);
        return nullptr;
    }

    if ((propertyMinuteVal < 0) || (propertyMinuteVal > maxMinute)) {
        ANSR_LOGE("Create alarm reminder fail: designated %{public}s must between [0, 59].",
            ReminderAgentNapi::ALARM_MINUTE);
        return nullptr;
    }

    // daysOfWeek
    std::vector<uint8_t> daysOfWeek;
    uint8_t maxDaysOfWeek = 7;
    if (ParseInt32Array(env, value, ReminderAgentNapi::REPEAT_DAYS_OF_WEEK, daysOfWeek, maxDaysOfWeek) == nullptr) {
        return nullptr;
    }
    reminder = std::make_shared<ReminderRequestAlarm>(
        static_cast<uint8_t>(propertyHourVal), static_cast<uint8_t>(propertyMinuteVal), daysOfWeek);
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value ReminderCommon::CreateReminderCalendar(
    const napi_env &env, const napi_value &value, const bool isSysApp, std::shared_ptr<ReminderRequest>& reminder)
{
    struct tm dateTime;
    napi_value dateTimeObj = nullptr;
    if (!GetObject(env, value, ReminderAgentNapi::CALENDAR_DATE_TIME, dateTimeObj)) {
        ANSR_LOGE("Create calendar reminder fail: dateTime must be setted.");
        return nullptr;
    }

    if (!ParseLocalDateTime(env, dateTimeObj, dateTime)) {
        ANSR_LOGE("Parce DateTime failed.");
        return nullptr;
    }

    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;

    if (!ParseCalendarParams(env, value, repeatMonths, repeatDays, daysOfWeek)) {
        return nullptr;
    }

    // rruleWantAgent
    std::shared_ptr<ReminderRequest::WantAgentInfo> wantAgentInfo;
    if (!GenWantAgent(env, value, ReminderAgentNapi::RRULL_WANT_AGENT, wantAgentInfo)) {
        return nullptr;
    }
    if (!isSysApp && wantAgentInfo != nullptr) {
        ANS_LOGE("Not system app rrule want info not supported");
        return nullptr;
    }
    
    auto reminderCalendar = std::make_shared<ReminderRequestCalendar>(dateTime, repeatMonths, repeatDays, daysOfWeek);
    napi_value endDateTimeObj = nullptr;
    if (GetObject(env, value, ReminderAgentNapi::CALENDAR_END_DATE_TIME, endDateTimeObj)) {
        struct tm endDateTime;
        if (!ParseLocalDateTime(env, endDateTimeObj, endDateTime)) {
            return nullptr;
        }
        time_t endTime = mktime(&endDateTime);
        if (endTime == -1) {
            return nullptr;
        }
        if (!reminderCalendar->SetEndDateTime(ReminderRequest::GetDurationSinceEpochInMilli(endTime))) {
            ANSR_LOGE("The end time must be greater than start time");
            return nullptr;
        }
    }
    
    if (!(reminderCalendar->InitTriggerTime())) {
        return nullptr;
    }
    reminderCalendar->SetRRuleWantAgentInfo(wantAgentInfo);
    reminder = reminderCalendar;
    return NotificationNapi::Common::NapiGetNull(env);
}

bool ReminderCommon::CheckCalendarParams(const int32_t &year, const int32_t &month, const int32_t &day,
    const int32_t &hour, const int32_t &min)
{
    if ((year < 0) || (year > UINT16_MAX)) {
        ANSR_LOGE("Create calendar reminder fail: designated %{public}s must between [0, %{public}d]",
            ReminderAgentNapi::CALENDAR_YEAR, UINT16_MAX);
        return false;
    }
    if ((month < 1) || (month > ReminderRequestCalendar::MAX_MONTHS_OF_YEAR)) {
        ANSR_LOGE("Create calendar reminder fail: designated %{public}s must between [1, %{public}hhu]",
            ReminderAgentNapi::CALENDAR_MONTH, ReminderRequestCalendar::MAX_MONTHS_OF_YEAR);
        return false;
    }
    uint8_t maxDaysOfMonth = ReminderRequestCalendar::GetDaysOfMonth(static_cast<uint16_t>(year), month);
    if ((day < 1) || (day > maxDaysOfMonth)) {
        ANSR_LOGE("Create calendar reminder fail: designated %{public}s must between [1, %{public}hhu]",
            ReminderAgentNapi::CALENDAR_DAY, maxDaysOfMonth);
        return false;
    }
    uint8_t maxHour = 23;
    if (hour < 0 || hour > maxHour) {
        ANSR_LOGE("Create calendar reminder fail: designated %{public}s must between [0, %{public}hhu]",
            ReminderAgentNapi::CALENDAR_HOUR, maxHour);
        return false;
    }
    uint8_t maxMinute = 59;
    if (min < 0 || min > maxMinute) {
        ANSR_LOGE("Create calendar reminder fail: designated %{public}s must between [0, %{public}hhu]",
            ReminderAgentNapi::CALENDAR_MINUTE, maxMinute);
        return false;
    }
    return true;
}

bool ReminderCommon::ParseCalendarParams(const napi_env& env, const napi_value& value,
    std::vector<uint8_t>& repeatMonths, std::vector<uint8_t>& repeatDays, std::vector<uint8_t>& daysOfWeek)
{
    // repeatMonth
    if (ParseInt32Array(env, value, ReminderAgentNapi::CALENDAR_REPEAT_MONTHS, repeatMonths,
        ReminderRequestCalendar::MAX_MONTHS_OF_YEAR) == nullptr) {
        return false;
    }

    // repeatDay
    if (ParseInt32Array(env, value, ReminderAgentNapi::CALENDAR_REPEAT_DAYS, repeatDays,
        ReminderRequestCalendar::MAX_DAYS_OF_MONTH) == nullptr) {
        return false;
    }

    // daysOfWeek
    uint8_t maxDaysOfWeek = 7;
    if (ParseInt32Array(env, value, ReminderAgentNapi::REPEAT_DAYS_OF_WEEK, daysOfWeek, maxDaysOfWeek) == nullptr) {
        return false;
    }
    
    return true;
}

bool ReminderCommon::ParseLocalDateTime(const napi_env& env, const napi_value& dateTimeObj, struct tm& dateTime)
{
    int32_t propertyYearVal = 0;
    int32_t propertyMonthVal = 0;
    int32_t propertyDayVal = 0;
    int32_t propertyHourVal = 0;
    int32_t propertyMinteVal = 0;
    if (!GetInt32(env, dateTimeObj, ReminderAgentNapi::CALENDAR_YEAR, propertyYearVal, true) ||
        !GetInt32(env, dateTimeObj, ReminderAgentNapi::CALENDAR_MONTH, propertyMonthVal, true) ||
        !GetInt32(env, dateTimeObj, ReminderAgentNapi::CALENDAR_DAY, propertyDayVal, true) ||
        !GetInt32(env, dateTimeObj, ReminderAgentNapi::CALENDAR_HOUR, propertyHourVal, true) ||
        !GetInt32(env, dateTimeObj, ReminderAgentNapi::CALENDAR_MINUTE, propertyMinteVal, true)) {
        return false;
    }

    if (!CheckCalendarParams(propertyYearVal, propertyMonthVal, propertyDayVal,
        propertyHourVal, propertyMinteVal)) {
        return false;
    }

    dateTime.tm_year = ReminderRequest::GetCTime(ReminderRequest::TimeTransferType::YEAR, propertyYearVal);
    dateTime.tm_mon = ReminderRequest::GetCTime(ReminderRequest::TimeTransferType::MONTH, propertyMonthVal);
    dateTime.tm_mday = propertyDayVal;
    dateTime.tm_hour = propertyHourVal;
    dateTime.tm_min = propertyMinteVal;
    dateTime.tm_sec = 0;
    dateTime.tm_isdst = -1;
    return true;
}

napi_value ReminderCommon::ParseInt32Array(const napi_env &env, const napi_value &value,
    const char* propertyName, std::vector<uint8_t> &propertyVal, uint8_t maxLen)
{
    napi_value result = nullptr;
    if (!GetObject(env, value, propertyName, result)) {
        return NotificationNapi::Common::NapiGetNull(env);
    }
    if (result != nullptr) {
        bool isArray = false;
        napi_is_array(env, result, &isArray);
        if (!isArray) {
            ANSR_LOGE("Property %{public}s is expected to be an array.", propertyName);
            return nullptr;
        }
        uint32_t length = 0;
        napi_get_array_length(env, result, &length);
        if (length > maxLen) {
            ANSR_LOGE("The max length of array of %{public}s is %{public}hhu.", propertyName, maxLen);
            return nullptr;
        }
        napi_valuetype valuetype = napi_undefined;
        for (size_t i = 0; i < length; i++) {
            int32_t propertyDayVal = 10;
            napi_value repeatDayVal = nullptr;
            napi_get_element(env, result, i, &repeatDayVal);
            NAPI_CALL(env, napi_typeof(env, repeatDayVal, &valuetype));
            if (valuetype != napi_number) {
                ANSR_LOGE("%{public}s's element is expected to be number.", propertyName);
                return nullptr;
            }
            napi_get_value_int32(env, repeatDayVal, &propertyDayVal);
            if (propertyDayVal < 1 || propertyDayVal > static_cast<int32_t>(maxLen)) {
                ANSR_LOGE("%{public}s's element must between [1, %{public}d].", propertyName, maxLen);
                return nullptr;
            }
            propertyVal.push_back(static_cast<uint8_t>(propertyDayVal));
        }
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

void ReminderCommon::PaddingCallbackPromiseInfo(
    const napi_env &env, const napi_ref &callback, CallbackPromiseInfo &info, napi_value &promise)
{
    if (callback) {
        info.callback = callback;
        info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        info.deferred = deferred;
        info.isCallback = false;
    }
}

void ReminderCommon::HandleErrCode(const napi_env &env, int32_t errCode)
{
    if (errCode == ERR_OK) {
        return;
    }
    std::string errCodeMsg = reminderErrCodeMsgMap[errCode];
    napi_throw_error(env, std::to_string(errCode).c_str(), errCodeMsg.c_str());
}

std::string ReminderCommon::FindErrMsg(const napi_env &env, const int32_t errCode)
{
    auto findMsg = reminderErrCodeMsgMap.find(errCode);
    if (findMsg == reminderErrCodeMsgMap.end()) {
        ANSR_LOGI("Inner error.");
        return "Inner error.";
    }
    return reminderErrCodeMsgMap[errCode];
}

void ReminderCommon::ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info,
    const napi_value &result, bool isThrow)
{
    ANSR_LOGI("enter errorCode=%{public}d", info.errorCode);
    if (info.isCallback) {
        if (isThrow) {
            SetCallback(env, info.callback, info.errorCode, result);
        } else {
            NotificationNapi::Common::SetCallback(env, info.callback, info.errorCode, result, false);
        }
    } else {
        SetPromise(env, info, result);
    }
    ANSR_LOGI("end");
}

void ReminderCommon::SetCallback(
    const napi_env &env, const napi_ref &callbackIn, const int32_t &errCode, const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_value results[ASYNC_CALLBACK_PARAM_NUM] = {nullptr};
    if (errCode == ERR_OK) {
        results[0] = NotificationNapi::Common::NapiGetNull(env);
    } else {
        std::string errMsg = FindErrMsg(env, errCode);
        results[0] = GetCallbackErrorValue(env, errCode, errMsg);
    }
    results[1] = result;
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, ASYNC_CALLBACK_PARAM_NUM, &results[0], &resultout));
}

napi_value ReminderCommon::GetCallbackErrorValue(napi_env env, const int32_t errCode, const std::string errMsg)
{
    if (errCode == ERR_OK) {
        return NotificationNapi::Common::NapiGetNull(env);
    }
    napi_value error = nullptr;
    napi_value eCode = nullptr;
    napi_value eMsg = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &eCode));
    NAPI_CALL(env, napi_create_string_utf8(env, errMsg.c_str(),
        errMsg.length(), &eMsg));
    NAPI_CALL(env, napi_create_object(env, &error));
    NAPI_CALL(env, napi_set_named_property(env, error, "code", eCode));
    NAPI_CALL(env, napi_set_named_property(env, error, "message", eMsg));
    return error;
}

napi_value  ReminderCommon::SetPromise(
    const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    if (info.errorCode == ERR_OK) {
        napi_resolve_deferred(env, info.deferred, result);
    } else {
        std::string errMsg = FindErrMsg(env, info.errorCode);
        if (errMsg == "") {
            return nullptr;
        }
        napi_value error = nullptr;
        napi_value eCode = nullptr;
        napi_value eMsg = nullptr;
        NAPI_CALL(env, napi_create_int32(env, info.errorCode, &eCode));
        NAPI_CALL(env, napi_create_string_utf8(env, errMsg.c_str(),
            errMsg.length(), &eMsg));
        NAPI_CALL(env, napi_create_object(env, &error));
        NAPI_CALL(env, napi_set_named_property(env, error, "data", eCode));
        NAPI_CALL(env, napi_set_named_property(env, error, "code", eCode));
        NAPI_CALL(env, napi_set_named_property(env, error, "message", eMsg));
        napi_reject_deferred(env, info.deferred, error);
    }
    return result;
}

napi_value ReminderCommon::JSParaError(const napi_env &env, const napi_ref &callback)
{
    if (callback) {
        SetCallback(env, callback, ERR_REMINDER_INVALID_PARAM, nullptr);
        return NotificationNapi::Common::NapiGetNull(env);
    } else {
        napi_value promise = nullptr;
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);

        napi_value res = nullptr;
        napi_value eCode = nullptr;
        napi_value eMsg = nullptr;
        std::string errMsg = FindErrMsg(env, ERR_REMINDER_INVALID_PARAM);
        NAPI_CALL(env, napi_create_int32(env, ERR_REMINDER_INVALID_PARAM, &eCode));
        NAPI_CALL(env, napi_create_string_utf8(env, errMsg.c_str(),
            errMsg.length(), &eMsg));
        NAPI_CALL(env, napi_create_object(env, &res));
        NAPI_CALL(env, napi_set_named_property(env, res, "data", eCode));
        NAPI_CALL(env, napi_set_named_property(env, res, "code", eCode));
        NAPI_CALL(env, napi_set_named_property(env, res, "message", eMsg));
        napi_reject_deferred(env, deferred, res);
        return promise;
    }
}
}
}
