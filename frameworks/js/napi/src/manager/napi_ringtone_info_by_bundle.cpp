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

#include "napi_ringtone_info_by_bundle.h"
#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
const int RINGTONE_INFO_BY_BUNDLE_MAX_PARA = 2;
const int RINGTONE_INFO_BY_BUNDLE_MIN_PARA = 1;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, RingtoneInfoByBundleParams &params)
{
    ANS_LOGD("enter");
    size_t argc = RINGTONE_INFO_BY_BUNDLE_MAX_PARA;
    napi_value argv[RINGTONE_INFO_BY_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < RINGTONE_INFO_BY_BUNDLE_MIN_PARA) {
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
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.bundle);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    if (argc > RINGTONE_INFO_BY_BUNDLE_MIN_PARA) {
        // argv[1]: ringtoneInfo
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto retValue = Common::GetRingtoneInfo(env, argv[PARAM1], params.ringtoneInfo);
        if (retValue == nullptr) {
            ANS_LOGE("GetRingtoneInfo failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiSetRingtoneInfoByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo = static_cast<AsyncCallbackRingtoneInfoByBundle *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiSetRingtoneInfoByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

void AsyncCompleteCallbackNapiGetRingtoneInfoByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo = static_cast<AsyncCallbackRingtoneInfoByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_object(env, &result);
            if (!Common::SetRingtoneInfo(env, asynccallbackinfo->params.ringtoneInfo, result)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiGetRingtoneInfoByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}
}  // namespace

napi_value NapiSetRingtoneInfoByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    RingtoneInfoByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackRingtoneInfoByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setRingtoneInfoByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetRingtoneInfoByBundle work excute.");
            AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackRingtoneInfoByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetRingtoneInfoByBundle(
                    asynccallbackinfo->params.bundle, asynccallbackinfo->params.ringtoneInfo);
                ANS_LOGI("SetRingtoneInfoByBundle errorCode=%{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetRingtoneInfoByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiGetRingtoneInfoByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    RingtoneInfoByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackRingtoneInfoByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getRingtoneInfoByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetRingtoneInfoByBundle work excute.");
            AsyncCallbackRingtoneInfoByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackRingtoneInfoByBundle *>(data);
            if (asynccallbackinfo) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetRingtoneInfoByBundle(
                        asynccallbackinfo->params.bundle, asynccallbackinfo->params.ringtoneInfo);
            }
        },
        AsyncCompleteCallbackNapiGetRingtoneInfoByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS