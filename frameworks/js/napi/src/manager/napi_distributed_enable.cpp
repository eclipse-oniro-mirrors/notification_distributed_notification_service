/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_distributed_enable.h"

#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {
const int SET_DISTRIBUTED_ENABLE_MAX_PARA = 3;
const int SET_DISTRIBUTED_ENABLE_MIN_PARA = 2;
const int SET_SMART_REMINDER_ENABLE_MAX_PARA = 2;
const int SET_SMART_REMINDER_ENABLE_MIN_PARA = 1;
const int SET_DISTRIBUTED_ENABLE_BY_SLOT_PARA = 3;
const int GET_DISTRIBUTED_ENABLE_BY_SLOT_PARA = 2;
static const std::set<std::string> DEVICE_TYPES = {"headset", "liteWearable", "wearable"};

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, DistributedEnableParams &params)
{
    ANS_LOGD("called");

    size_t argc = SET_DISTRIBUTED_ENABLE_MAX_PARA;
    napi_value argv[SET_DISTRIBUTED_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_DISTRIBUTED_ENABLE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundleOption
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Parameter type error. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("null retValue");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: deviceType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen);
    if (std::strlen(str) == 0) {
        ANS_LOGE("Property deviceType is empty");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    params.deviceType = str;

    if (argc > SET_DISTRIBUTED_ENABLE_MIN_PARA) {
        // argv[2]: enable
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, argv[PARAM2], &params.enable);
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiSetDistributedEnabledByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackDistributedEnable *asynccallbackinfo = static_cast<AsyncCallbackDistributedEnable *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiSetDistributedEnableByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiSetDistributedEnabledByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    DistributedEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackDistributedEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackDistributedEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "distributedEnableByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetDistributedEnableByBundle work excute.");
            AsyncCallbackDistributedEnable *asynccallbackinfo = static_cast<AsyncCallbackDistributedEnable *>(data);
            if (asynccallbackinfo) {
                std::string deviceType = asynccallbackinfo->params.deviceType;
                asynccallbackinfo->info.errorCode = NotificationHelper::SetDistributedEnabledByBundle(
                    asynccallbackinfo->params.option, deviceType, asynccallbackinfo->params.enable);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetDistributedEnabledByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

void AsyncCompleteCallbackNapiSetSmartReminderEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackSmartReminderEnabled *asynccallbackinfo = static_cast<AsyncCallbackSmartReminderEnabled *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiSetSmartReminderEnabled callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, SmartReminderEnabledParams &params)
{
    ANS_LOGD("called");

    size_t argc = SET_SMART_REMINDER_ENABLE_MAX_PARA;
    napi_value argv[SET_SMART_REMINDER_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_SMART_REMINDER_ENABLE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: deviceType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[PARAM0], str, STR_MAX_SIZE - 1, &strLen);
    if (std::strlen(str) == 0) {
        ANS_LOGE("Property deviceType is empty");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    params.deviceType = str;

    if (argc > SET_SMART_REMINDER_ENABLE_MIN_PARA) {
        // argv[1]: enable
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, argv[PARAM1], &params.enable);
    }

    return Common::NapiGetNull(env);
}

napi_value NapiSetSmartReminderEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    SmartReminderEnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackSmartReminderEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackSmartReminderEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSmartReminderEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetSmartReminderEnabled work excute.");
            AsyncCallbackSmartReminderEnabled *asynccallbackinfo =
                static_cast<AsyncCallbackSmartReminderEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetSmartReminderEnabled(
                    asynccallbackinfo->params.deviceType, asynccallbackinfo->params.enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetSmartReminderEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackNapiIsSmartReminderEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsSmartReminderEnabled napi_create_async_work end");
    AsyncCallbackSmartReminderEnabled *asynccallbackinfo = static_cast<AsyncCallbackSmartReminderEnabled *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->params.enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiIsSmartReminderEnabled callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsSmartReminderEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    SmartReminderEnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackSmartReminderEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackSmartReminderEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isSmartReminderEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsSmartReminderEnabled work excute.");
            AsyncCallbackSmartReminderEnabled *asynccallbackinfo =
                static_cast<AsyncCallbackSmartReminderEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsSmartReminderEnabled(
                    asynccallbackinfo->params.deviceType, asynccallbackinfo->params.enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiIsSmartReminderEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value ParseParameters(const napi_env &env,
    const napi_callback_info &info, DistributedEnableBySlotParams &params, bool setOperation)
{
    ANS_LOGD("called");
    size_t argc = SET_DISTRIBUTED_ENABLE_BY_SLOT_PARA;
    napi_value argv[SET_DISTRIBUTED_ENABLE_BY_SLOT_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if ((setOperation && argc != SET_DISTRIBUTED_ENABLE_BY_SLOT_PARA) ||
        (!setOperation && argc != GET_DISTRIBUTED_ENABLE_BY_SLOT_PARA)) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: slot
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Parameter type error. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int32_t slotType;
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &slotType));
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), outType)) {
        std::string msg = "Incorrect parameter slot.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    params.slot = outType;
    
    // argv[1]: deviceType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen);
    if (std::strlen(str) == 0) {
        ANS_LOGE("Property deviceType is empty");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    if (DEVICE_TYPES.find(str) == DEVICE_TYPES.end()) {
        ANS_LOGE("Property deviceType is not allowed");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    params.deviceType = str;

    // argv[2]: enable
    if (setOperation) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, argv[PARAM2], &params.enable);
    }
    
    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiSetDistributedEnabledBySlot(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackDistributedEnableBySlot *asynccallbackinfo = static_cast<AsyncCallbackDistributedEnableBySlot *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiSetDistributedEnabledBySlot callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiSetDistributedEnabledBySlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    DistributedEnableBySlotParams params {};
    if (ParseParameters(env, info, params, true) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackDistributedEnableBySlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackDistributedEnableBySlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setDistributedEnabledBySlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetDistributedEnabledBySlot work excute.");
            AsyncCallbackDistributedEnableBySlot *asynccallbackinfo =
                static_cast<AsyncCallbackDistributedEnableBySlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetDistributedEnabledBySlot(
                    asynccallbackinfo->params.slot,
                    asynccallbackinfo->params.deviceType,
                    asynccallbackinfo->params.enable);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetDistributedEnabledBySlot,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

void AsyncCompleteCallbackNapiIsDistributedEnabledBySlot(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsDistributedEnabledBySlot napi_create_async_work end");
    AsyncCallbackDistributedEnableBySlot *asynccallbackinfo = static_cast<AsyncCallbackDistributedEnableBySlot *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->params.enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiIsDistributedEnabledBySlot callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsDistributedEnabledBySlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    DistributedEnableBySlotParams params {};
    if (ParseParameters(env, info, params, false) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackDistributedEnableBySlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackDistributedEnableBySlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isDistributedEnabledBySlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsDistributedEnabledBySlot work excute.");
            AsyncCallbackDistributedEnableBySlot *asynccallbackinfo =
                static_cast<AsyncCallbackDistributedEnableBySlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsDistributedEnabledBySlot(
                    asynccallbackinfo->params.slot,
                    asynccallbackinfo->params.deviceType,
                    asynccallbackinfo->params.enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiIsDistributedEnabledBySlot,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
