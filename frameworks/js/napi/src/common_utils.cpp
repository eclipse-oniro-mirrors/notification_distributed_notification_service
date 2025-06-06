/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "common.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_action_button.h"
#include "notification_capsule.h"
#include "notification_constant.h"
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
const uint32_t MAX_PARAM_NUM = 5;

napi_value Common::NapiGetBoolean(napi_env env, const bool &isValue)
{
    napi_value result = nullptr;
    napi_get_boolean(env, isValue, &result);
    return result;
}

napi_value Common::NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value Common::NapiGetUndefined(napi_env env)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value Common::CreateErrorValue(napi_env env, int32_t errCode, bool newType)
{
    ANS_LOGI("enter, errorCode[%{public}d]", errCode);
    napi_value error = Common::NapiGetNull(env);
    if (errCode == ERR_OK && newType) {
        return error;
    }

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);

    std::string errMsg = OHOS::Notification::GetAnsErrMessage(errCode);
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);

    napi_create_error(env, nullptr, message, &error);
    napi_set_named_property(env, error, "code", code);
    return error;
}

napi_value Common::CreateErrorValue(napi_env env, int32_t errCode, std::string &msg)
{
    ANS_LOGI("enter, errorCode[%{public}d]", errCode);
    napi_value error = Common::NapiGetNull(env);
    if (errCode == ERR_OK) {
        return error;
    }

    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);

    std::string errMsg = OHOS::Notification::GetAnsErrMessage(errCode);
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.append(" ").append(msg).c_str(), NAPI_AUTO_LENGTH, &message);

    napi_create_error(env, nullptr, message, &error);
    napi_set_named_property(env, error, "code", code);
    return error;
}

void Common::NapiThrow(napi_env env, int32_t errCode)
{
    ANS_LOGD("enter");

    napi_throw(env, CreateErrorValue(env, errCode, true));
}

void Common::NapiThrow(napi_env env, int32_t errCode, std::string &msg)
{
    ANS_LOGD("enter");

    napi_throw(env, CreateErrorValue(env, errCode, msg));
}

napi_value Common::GetCallbackErrorValue(napi_env env, int32_t errCode)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &eCode));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));
    return result;
}

void Common::PaddingCallbackPromiseInfo(
    const napi_env &env, const napi_ref &callback, CallbackPromiseInfo &info, napi_value &promise)
{
    ANS_LOGD("enter");

    if (callback) {
        ANS_LOGD("Callback is not nullptr.");
        info.callback = callback;
        info.isCallback = true;
    } else {
        napi_deferred deferred = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, &deferred, &promise));
        info.deferred = deferred;
        info.isCallback = false;
    }
}

void Common::ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    ANS_LOGD("enter errorCode=%{public}d", info.errorCode);
    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, result, false);
    } else {
        SetPromise(env, info.deferred, info.errorCode, result, false);
    }
    ANS_LOGD("end");
}

void Common::SetCallback(
    const napi_env &env, const napi_ref &callbackIn, const int32_t &errorCode, const napi_value &result, bool newType)
{
    ANS_LOGD("enter");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_value results[ARGS_TWO] = {nullptr};
    results[PARAM0] = CreateErrorValue(env, errorCode, newType);
    results[PARAM1] = result;
    napi_status napi_result = napi_call_function(env, undefined, callback, ARGS_TWO, &results[PARAM0], &resultout);
    if (napi_result != napi_ok) {
        ANS_LOGE("napi_call_function failed, result = %{public}d", napi_result);
    }
    NAPI_CALL_RETURN_VOID(env, napi_result);
    ANS_LOGI("end");
}

void Common::SetCallback(
    const napi_env &env, const napi_ref &callbackIn, const napi_value &result)
{
    ANS_LOGD("enter");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_status napi_result = napi_call_function(env, undefined, callback, ARGS_ONE, &result, &resultout);
    if (napi_result != napi_ok) {
        ANS_LOGE("napi_call_function failed, result = %{public}d", napi_result);
    }
    NAPI_CALL_RETURN_VOID(env, napi_result);
    ANS_LOGI("end");
}

void Common::SetCallbackArg2(
    const napi_env &env, const napi_ref &callbackIn, const napi_value &result0, const napi_value &result1)
{
    ANS_LOGD("enter");
    napi_value result[ARGS_TWO] = {result0, result1};
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_status napi_result = napi_call_function(env, undefined, callback, ARGS_TWO, result, &resultout);
    if (napi_result != napi_ok) {
        ANS_LOGE("napi_call_function failed, result = %{public}d", napi_result);
    }
    NAPI_CALL_RETURN_VOID(env, napi_result);
    ANS_LOGI("end");
}

void Common::SetPromise(const napi_env &env,
    const napi_deferred &deferred, const int32_t &errorCode, const napi_value &result, bool newType)
{
    ANS_LOGD("enter");
    if (errorCode == ERR_OK) {
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred, CreateErrorValue(env, errorCode, newType));
    }
    ANS_LOGD("end");
}

napi_value Common::JSParaError(const napi_env &env, const napi_ref &callback)
{
    if (callback) {
        return Common::NapiGetNull(env);
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_create_promise(env, &deferred, &promise);
    SetPromise(env, deferred, ERROR, Common::NapiGetNull(env), false);
    return promise;
}

napi_value Common::ParseParaOnlyCallback(const napi_env &env, const napi_callback_info &info, napi_ref &callback)
{
    ANS_LOGD("enter");

    size_t argc = ONLY_CALLBACK_MAX_PARA;
    napi_value argv[ONLY_CALLBACK_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ONLY_CALLBACK_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]:callback
    napi_valuetype valuetype = napi_undefined;
    if (argc >= ONLY_CALLBACK_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM0], 1, &callback);
    }

    return Common::NapiGetNull(env);
}

void Common::CreateReturnValue(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    ANS_LOGD("enter errorCode=%{public}d", info.errorCode);
    int32_t errorCode = info.errorCode == ERR_OK ? ERR_OK : ErrorToExternal(info.errorCode);
    if (info.isCallback) {
        SetCallback(env, info.callback, errorCode, result, true);
    } else {
        SetPromise(env, info.deferred, errorCode, result, true);
    }
    ANS_LOGD("end");
}

napi_value Common::NapiReturnCapErrCb(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_PARAM_NUM;
    napi_value argv[MAX_PARAM_NUM] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    for (size_t i = 0; i < argc && i < MAX_PARAM_NUM; ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valuetype));
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[i], 1, &callback);
            SetCallback(env, callback, ERROR_SYSTEM_CAP_ERROR, nullptr, false);
            napi_delete_reference(env, callback);
            return NapiGetNull(env);
        }
    }

    return NapiReturnCapErr(env, info);
}

napi_value Common::NapiReturnCapErr(napi_env env, napi_callback_info info)
{
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_create_promise(env, &deferred, &promise);
    SetPromise(env, deferred, ERROR_SYSTEM_CAP_ERROR, Common::NapiGetNull(env), false);
    return promise;
}

napi_value Common::NapiReturnFalseCb(napi_env env, napi_callback_info info)
{
    return Common::NapiReturnFalseCbInner(env, info, false);
}

napi_value Common::NapiReturnFalseCbNewType(napi_env env, napi_callback_info info)
{
    return Common::NapiReturnFalseCbInner(env, info, true);
}

napi_value Common::NapiReturnFalseCbInner(napi_env env, napi_callback_info info, bool newType)
{
    size_t argc = ONLY_CALLBACK_MAX_PARA;
    napi_value argv[ONLY_CALLBACK_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    napi_value result = nullptr;
    napi_get_boolean(env, false, &result);
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc >= ONLY_CALLBACK_MIN_PARA) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[PARAM0], 1, &callback);
            SetCallback(env, callback, 0, result, true);
            napi_delete_reference(env, callback);
            return NapiGetNull(env);
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_create_promise(env, &deferred, &promise);
    SetPromise(env, deferred, 0, result, false);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
