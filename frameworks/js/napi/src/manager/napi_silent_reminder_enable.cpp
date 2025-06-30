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

#include "napi_silent_reminder_enable.h"

#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {

const int SET_SILENT_REMINDER_ENABLE_MAX_PARA = 2;
const int SET_SILENT_REMINDER_ENABLE_MIN_PARA = 1;

void AsyncCompleteCallbackNapiSetSilentReminderEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackSilentReminderEnable *asynccallbackinfo = static_cast<AsyncCallbackSilentReminderEnable *>(data);
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

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, SilentReminderEnableParams &params)
{
    ANS_LOGD("enter");
 
    size_t argc = SET_SILENT_REMINDER_ENABLE_MAX_PARA;
    napi_value argv[SET_SILENT_REMINDER_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_SILENT_REMINDER_ENABLE_MIN_PARA) {
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
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }
 
    if (argc > SET_SILENT_REMINDER_ENABLE_MIN_PARA) {
        // argv[2]: enable
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types.The type of param must be boolean.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, argv[PARAM1], &params.enabled);
    }
 
    return Common::NapiGetNull(env);
}

napi_value NapiSetSilentReminderEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    SilentReminderEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
 
    AsyncCallbackSilentReminderEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackSilentReminderEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
 
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSilentReminderEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetSilentReminderEnabled work excute.");
            AsyncCallbackSilentReminderEnable *asynccallbackinfo = static_cast<AsyncCallbackSilentReminderEnable *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetSilentReminderEnabled(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enabled);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetSilentReminderEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
 
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
 
    return promise;
 
}
 
void AsyncCompleteCallbackNapiIsSilentReminderEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsSmartReminderEnabled napi_create_async_work end");
    AsyncCallbackSilentReminderEnable *asynccallbackinfo = static_cast<AsyncCallbackSilentReminderEnable *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_int32(env, asynccallbackinfo->params.enableStatus, &result);
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
 
napi_value NapiIsSilentReminderEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    SilentReminderEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
 
    AsyncCallbackSilentReminderEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackSilentReminderEnable {.env = env, .asyncWork = nullptr, .params = params};
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
            AsyncCallbackSilentReminderEnable *asynccallbackinfo =
                static_cast<AsyncCallbackSilentReminderEnable *>(data);
            if (asynccallbackinfo) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsSilentReminderEnabled(
                        asynccallbackinfo->params.option, asynccallbackinfo->params.enableStatus);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d, enableStatus = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->params.enableStatus);
            }
        },
        AsyncCompleteCallbackNapiIsSilentReminderEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
 
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}
}