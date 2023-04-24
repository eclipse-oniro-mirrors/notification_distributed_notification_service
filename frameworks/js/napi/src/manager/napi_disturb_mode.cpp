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
#include "napi_disturb_mode.h"

#include "ans_inner_errors.h"
#include "disturb_mode.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiSetDoNotDisturbDate(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    SetDoNotDisturbDateParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetDoNotDisturb {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setDoNotDisturbDate", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr, resourceName, [](napi_env env, void *data) {
            ANS_LOGI("SetDoNotDisturbDate napi_create_async_work start");
            AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoSetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::SetDoNotDisturbDate(
                        asynccallbackinfo->params.userId, asynccallbackinfo->params.date);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::SetDoNotDisturbDate(
                        asynccallbackinfo->params.date);
                }

                ANS_LOGI("SetDoNotDisturbDate date=%{public}s errorCode=%{public}d, hasUserId=%{public}d",
                    asynccallbackinfo->params.date.Dump().c_str(), asynccallbackinfo->info.errorCode,
                    asynccallbackinfo->params.hasUserId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("SetDoNotDisturbDate napi_create_async_work end");
            AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoSetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetDoNotDisturbDate(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoGetDoNotDisturb *>(data);
    if (asynccallbackinfo) {
        napi_value result = Common::NapiGetNull(env);
        if (asynccallbackinfo->info.errorCode == ERR_OK) {
            napi_create_object(env, &result);
            if (!Common::SetDoNotDisturbDate(env, asynccallbackinfo->date, result)) {
                asynccallbackinfo->info.errorCode = ERROR;
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetDoNotDisturbDate(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    GetDoNotDisturbDateParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetDoNotDisturb {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getDoNotDisturbDate", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetDoNotDisturbDate napi_create_async_work start");
            AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoGetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetDoNotDisturbDate(
                        asynccallbackinfo->params.userId, asynccallbackinfo->date);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetDoNotDisturbDate(
                        asynccallbackinfo->date);
                }

                ANS_LOGI("GetDoNotDisturbDate errorCode=%{public}d date=%{public}s, hasUserId=%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->date.Dump().c_str(),
                    asynccallbackinfo->params.hasUserId);
            }
        },
        AsyncCompleteCallbackNapiGetDoNotDisturbDate,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSupportDoNotDisturbMode(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSupportDoNotDisturb {
        .env = env, .asyncWork = nullptr, .callback = callback};

    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "supportDoNotDisturbMode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("SupportDoNotDisturbMode napi_create_async_work start");
            AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
                static_cast<AsyncCallbackInfoSupportDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::DoesSupportDoNotDisturbMode(asynccallbackinfo->isSupported);
                ANS_LOGI("SupportDoNotDisturbMode errorCode=%{public}d isSupported=%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->isSupported);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("SupportDoNotDisturbMode napi_create_async_work end");
            AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
                static_cast<AsyncCallbackInfoSupportDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asynccallbackinfo->isSupported, &result);
                Common::CreateReturnValue(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS