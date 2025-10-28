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

#include "napi_priority.h"

#include "ans_inner_errors.h"
#include "priority.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiSetPriorityEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    EnabledParams params{};
    if (ParsePriorityParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled{ .env = env, .asyncWork = nullptr, .params = params };
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asyncCallbackinfo fail.");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setPriorityEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetPriorityEnabled work excute.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::SetPriorityEnabled(asynccallbackinfo->params.enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetPriorityEnabled work complete.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete NapiSetPriorityEnabled callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetPriorityEnabled work complete end.");
        },
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value NapiSetPriorityEnabledByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    EnabledByBundleParams params{};
    if (ParsePriorityParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = new (std::nothrow)AsyncCallbackInfoEnabledByBundle{
        .env = env, .asyncWork = nullptr, .option = params.option, .enable = params.enable };
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asyncCallbackinfo fail.");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setPriorityEnabledByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetPriorityEnabledByBundle work excute.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetPriorityEnabledByBundle(
                    asynccallbackinfo->option, asynccallbackinfo->enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetPriorityEnabledByBundle work complete.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete NapiSetPriorityEnabledByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetPriorityEnabledByBundle work complete end.");
        },
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackNapiIsPriorityEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGD("IsPriorityEnabled napi_create_async_work end");
    AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiIsPriorityEnabled callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsPriorityEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    EnabledParams params{};
    if (ParseIsPriorityEnabledParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_ref callback = params.callback;
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnabled { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isPriorityEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsPriorityEnabled work excute.");
            AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsPriorityEnabled(asynccallbackinfo->enable);
                ANS_LOGI("IsPriorityEnabled enable=%{public}d", asynccallbackinfo->enable);
            }
        }, AsyncCompleteCallbackNapiIsPriorityEnabled, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiIsPriorityEnabledByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGD("IsPriorityEnabledByBundle napi_create_async_work end");
    AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo =
        static_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiIsPriorityEnabledByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsPriorityEnabledByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    EnabledByBundleParams params{};
    if (ParseIsPriorityEnabledParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_ref callback = params.callback;
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnabledByBundle {
        .env = env, .asyncWork = nullptr, .option = params.option };
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isPriorityEnabledByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsPriorityEnabledByBundle work excute.");
            AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsPriorityEnabledByBundle(
                    asynccallbackinfo->option, asynccallbackinfo->enable);
                ANS_LOGI("IsPriorityEnabledByBundle enable=%{public}d", asynccallbackinfo->enable);
            }
        }, AsyncCompleteCallbackNapiIsPriorityEnabledByBundle,
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS