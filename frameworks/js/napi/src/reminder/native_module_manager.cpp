/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "reminder/native_module_manager.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "reminder/publish.h"
#include "manager/napi_slot.h"

namespace OHOS {
namespace ReminderAgentNapi {
EXTERN_C_START
napi_value ReminderAgentManagerInit(napi_env env, napi_value exports)
{
    ANSR_LOGI("ReminderAgentManagerInit start");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("cancelReminder", CancelReminderMgr),
        DECLARE_NAPI_FUNCTION("cancelAllReminders", CancelAllRemindersMgr),
        DECLARE_NAPI_FUNCTION("getValidReminders", GetValidRemindersMgr),
        DECLARE_NAPI_FUNCTION("getAllValidReminders", GetAllValidRemindersMgr),
        DECLARE_NAPI_FUNCTION("publishReminder", PublishReminderMgr),
        DECLARE_NAPI_FUNCTION("addNotificationSlot", AddSlotMgr),
        DECLARE_NAPI_FUNCTION("removeNotificationSlot", NotificationNapi::NapiRemoveSlot),
        DECLARE_NAPI_FUNCTION("addExcludeDate", AddExcludeDate),
        DECLARE_NAPI_FUNCTION("deleteExcludeDates", DelExcludeDates),
        DECLARE_NAPI_FUNCTION("getExcludeDates", GetExcludeDates),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

napi_value ConstantInit(napi_env env, napi_value exports)
{
    ANSR_LOGI("ConstantInit start");
    napi_value objReminderType = nullptr;
    napi_create_object(env, &objReminderType);

    napi_value prop = nullptr;
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ReminderType::TIMER), &prop) == napi_ok) {
        napi_set_named_property(env, objReminderType, "REMINDER_TYPE_TIMER", prop);
    }
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ReminderType::ALARM), &prop) == napi_ok) {
        napi_set_named_property(env, objReminderType, "REMINDER_TYPE_ALARM", prop);
    }
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ReminderType::CALENDAR), &prop) == napi_ok) {
        napi_set_named_property(env, objReminderType, "REMINDER_TYPE_CALENDAR", prop);
    }

    napi_value objButtonType = nullptr;
    napi_create_object(env, &objButtonType);
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ActionButtonType::CLOSE), &prop) == napi_ok) {
        napi_set_named_property(env, objButtonType, "ACTION_BUTTON_TYPE_CLOSE", prop);
    }
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ActionButtonType::SNOOZE), &prop) == napi_ok) {
        napi_set_named_property(env, objButtonType, "ACTION_BUTTON_TYPE_SNOOZE", prop);
    }
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::ActionButtonType::CUSTOM), &prop) == napi_ok) {
        napi_set_named_property(env, objButtonType, "ACTION_BUTTON_TYPE_CUSTOM", prop);
    }

    napi_value objRingChannel = nullptr;
    napi_create_object(env, &objRingChannel);
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::RingChannel::MEDIA), &prop) == napi_ok) {
        napi_set_named_property(env, objRingChannel, "RING_CHANNEL_MEDIA", prop);
    }
    if (napi_create_int32(env, static_cast<int32_t>(ReminderRequest::RingChannel::ALARM), &prop) == napi_ok) {
        napi_set_named_property(env, objRingChannel, "RING_CHANNEL_ALARM", prop);
    }

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("ReminderType", objReminderType),
        DECLARE_NAPI_PROPERTY("ActionButtonType", objButtonType),
        DECLARE_NAPI_PROPERTY("RingChannel", objRingChannel),
    };

    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
    return exports;
};
EXTERN_C_END

/*
 * Module define
 */
static napi_module _apiModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = ManagerInit,
    .nm_modname = "reminderAgentManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

/*
 * function for module exports
 */
static napi_value ManagerInit(napi_env env, napi_value exports)
{
    ReminderAgentManagerInit(env, exports);
    ConstantInit(env, exports);
    return exports;
}

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_apiModule);
}
}  // namespace ReminderAgentNapi
}  // namespace OHOS