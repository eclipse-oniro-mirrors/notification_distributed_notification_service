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
        ANS_LOGE("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }
    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled { .env = env, .asyncWork = nullptr, .enable = params.enable };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setPriorityEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiSetPriorityEnabled work excute.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::SetPriorityEnabled(asynccallbackinfo->enable);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [] (napi_env env, napi_status status, void *data) {
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
        }, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value NapiSetPriorityEnabledByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    EnabledByBundleParams params{};
    if (ParsePriorityParameters(env, info, params) == nullptr) {
        ANS_LOGE("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }
    AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoEnabledByBundle {
        .env = env, .asyncWork = nullptr, .option = params.option, .enableStatus = params.enableStatus };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setPriorityEnabledByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiSetPriorityEnabledByBundle work excute.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetPriorityEnabledByBundle(
                    asynccallbackinfo->option, asynccallbackinfo->enableStatus);
                ANS_LOGD("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [] (napi_env env, napi_status status, void *data) {
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
        }, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
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
    AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
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
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoEnabled {
        .env = env, .asyncWork = nullptr, .enable = false };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isPriorityEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiIsPriorityEnabled work excute.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsPriorityEnabled(asynccallbackinfo->enable);
                ANS_LOGI("IsPriorityEnabled enable=%{public}d", asynccallbackinfo->enable);
            }
        }, AsyncCompleteCallbackNapiIsPriorityEnabled, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackNapiIsPriorityEnabledByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGD("IsPriorityEnabledByBundle napi_create_async_work end");
    AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_int32(env, static_cast<int32_t>(asynccallbackinfo->enableStatus), &result);
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
        ANS_LOGE("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoEnabledByBundle {
        .env = env, .asyncWork = nullptr, .option = params.option,
        .enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isPriorityEnabledByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiIsPriorityEnabledByBundle work excute.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackInfoEnabledByBundle *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::IsPriorityEnabledByBundle(
                    asynccallbackinfo->option, asynccallbackinfo->enableStatus);
            }
        }, AsyncCompleteCallbackNapiIsPriorityEnabledByBundle,
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value NapiSetBundlePriorityConfig(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ConfigByBundleParams params{};
    if (ParsePriorityParameters(env, info, params) == nullptr) {
        ANS_LOGE("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }
    AsyncCallbackInfoConfigByBundle *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoConfigByBundle {
        .env = env, .asyncWork = nullptr, .option = params.option, .configValue = params.configValue };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setBundlePriorityConfig", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiSetBundlePriorityConfig work excute.");
            AsyncCallbackInfoConfigByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoConfigByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetBundlePriorityConfig(
                    asynccallbackinfo->option, asynccallbackinfo->configValue);
                ANS_LOGD("NapiSetBundlePriorityConfig errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        }, [] (napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetBundlePriorityConfig work complete.");
            AsyncCallbackInfoConfigByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoConfigByBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete NapiSetBundlePriorityConfig callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetBundlePriorityConfig work complete end.");
        }, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackNapiGetBundlePriorityConfig(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGD("GetBundlePriorityConfig napi_create_async_work end");
    AsyncCallbackInfoConfigByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoConfigByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_string_utf8(env, asynccallbackinfo->configValue.c_str(), NAPI_AUTO_LENGTH, &result);
            napi_set_named_property(env, result, "value", result);
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

napi_value NapiGetBundlePriorityConfig(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ConfigByBundleParams params{};
    if (ParseGetPriorityConfigParameters(env, info, params) == nullptr) {
        ANS_LOGE("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoConfigByBundle {
        .env = env, .asyncWork = nullptr, .option = params.option, .configValue = "" };
    if (!asynccallbackinfo) {
        ANS_LOGE("Create asyncCallbackinfo fail.");
        std::string msg = "Low memory.";
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR, msg);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getBundlePriorityConfig", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env, nullptr, resourceName,
        [] (napi_env env, void *data) {
            ANS_LOGD("NapiGetBundlePriorityConfig work excute.");
            AsyncCallbackInfoConfigByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoConfigByBundle *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetBundlePriorityConfig(
                    asynccallbackinfo->option, asynccallbackinfo->configValue);
            }
        }, AsyncCompleteCallbackNapiGetBundlePriorityConfig,
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS