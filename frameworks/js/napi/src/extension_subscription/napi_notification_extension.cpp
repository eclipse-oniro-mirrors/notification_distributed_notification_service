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

#include "napi_notification_extension.h"

#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
const int SUBSCRIBE_MAX_PARA = 1;
const int NAPI_GET_USER_GRANTED_STATE_MAX_PARA = 1;
const int NAPI_SET_USER_GRANTED_STATE_MAX_PARA = 2;
const int NAPI_GET_USER_GRANTED_ENABLE_BUNDLES_MAX_PARA = 1;
const int NAPI_SET_USER_GRANTED_BUNDLE_STATE_MAX_PARA = 3;
}

napi_value ParseParametersForGetUserGrantedState(const napi_env& env, const napi_callback_info& info,
    NotificationExtensionUserGrantedParams& params)
{
    size_t argc = NAPI_GET_USER_GRANTED_STATE_MAX_PARA;
    napi_value argv[NAPI_GET_USER_GRANTED_STATE_MAX_PARA] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < NAPI_GET_USER_GRANTED_STATE_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: targetBundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Argument type is incorrect. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.targetBundle);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParametersForSetUserGrantedState(const napi_env& env, const napi_callback_info& info,
    NotificationExtensionUserGrantedParams& params)
{
    size_t argc = NAPI_SET_USER_GRANTED_STATE_MAX_PARA;
    napi_value argv[NAPI_SET_USER_GRANTED_STATE_MAX_PARA] = { nullptr, nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < NAPI_SET_USER_GRANTED_STATE_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: targetBundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Argument type is incorrect. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.targetBundle);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: enabled
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM1], &params.enabled);

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackUserGrantedReturnVoid(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo =
        static_cast<AsyncCallbackInfoNotificationExtensionUserGranted*>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

void AsyncCompleteCallbackReturnBoolean(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo =
        static_cast<AsyncCallbackInfoNotificationExtensionUserGranted*>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->params.enabled, &result);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsUserGranted(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiIsUserGranted called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isUserGranted", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("isUserGranted work excute.");
            AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::IsUserGranted(asynccallbackinfo->params.enabled);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackReturnBoolean,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiGetUserGrantedState(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    if (ParseParametersForGetUserGrantedState(env, info, asynccallbackinfo->params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getUserGrantedState", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("getUserGrantedState work excute.");
            AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetUserGrantedState(
                    asynccallbackinfo->params.targetBundle, asynccallbackinfo->params.enabled);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackReturnBoolean,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiSetUserGrantedState(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    if (ParseParametersForSetUserGrantedState(env, info, asynccallbackinfo->params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setUserGrantedState", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("setUserGrantedState work excute.");
            AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetUserGrantedState(
                    asynccallbackinfo->params.targetBundle, asynccallbackinfo->params.enabled);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackUserGrantedReturnVoid,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
