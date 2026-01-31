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
const int32_t GET_PRIORITY_ENABLE_MAX_PARA = 1;
const int32_t SET_PRIORITY_ENABLE_MAX_PARA = 1;

struct AsyncCallbackInfoPriorityEnabled {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<NotificationBundleOption> bundles;
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    CallbackPromiseInfo info;
};

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


napi_value ParseParametersForBundles(const napi_env &env, const napi_callback_info &info,
    std::vector<NotificationBundleOption> &bundles)
{
    ANS_LOGD("ParseParametersForBundles");
    size_t argc = GET_PRIORITY_ENABLE_MAX_PARA;
    napi_value argv[GET_PRIORITY_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc != GET_PRIORITY_ENABLE_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, argv[PARAM0], &isArray));
    if (!isArray) {
        ANS_LOGE("Parameter type error. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    uint32_t len = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[PARAM0], &len));
    if (len == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    for (uint32_t index = 0; index < len; ++index) {
        napi_value nBundle = nullptr;
        NAPI_CALL(env, napi_get_element(env, argv[PARAM0], index, &nBundle));
        NAPI_CALL(env, napi_typeof(env, nBundle, &valueType));
        if (valueType != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NotificationBundleOption bundle;
        if (!Common::GetBundleOption(env, nBundle, bundle)) {
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        bundles.emplace_back(bundle);
    }
    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiGetPriorityEnabledByBundles(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiGetPriorityEnabledByBundles work complete.");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoPriorityEnabled *asyncCallbackInfo = static_cast<AsyncCallbackInfoPriorityEnabled*>(data);
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("null asyncCallbackInfo");
        return;
    }
    napi_value resultMap;
    napi_create_map(env, &resultMap);

    for (auto itr = asyncCallbackInfo->priorityEnable.begin(); itr != asyncCallbackInfo->priorityEnable.end(); ++itr) {
        if (itr->first == nullptr) {
            continue;
        }
        napi_value jsKey;
        napi_create_object(env, &jsKey);
        napi_value bundleValue;
        napi_create_string_utf8(env, itr->first->GetBundleName().c_str(), NAPI_AUTO_LENGTH, &bundleValue);
        napi_set_named_property(env, jsKey, "bundle", bundleValue);
        napi_value uidValue;
        napi_create_int32(env, itr->first->GetUid(), &uidValue);
        napi_set_named_property(env, jsKey, "uid", uidValue);
        napi_value jsValue;
        napi_get_boolean(env, itr->second, &jsValue);
        napi_map_set_property(env, resultMap, jsKey, jsValue);
    }
    if (asyncCallbackInfo->priorityEnable.empty()) {
        ANS_LOGW("PriorityEnable is empty.");
        resultMap  = Common::NapiGetNull(env);
    }

    Common::CreateReturnValue(env, asyncCallbackInfo->info, resultMap);
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
    return;
}

napi_value NapiGetPriorityEnabledByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiGetPriorityEnabledByBundles");
    std::vector<NotificationBundleOption> bundles;
    if (ParseParametersForBundles(env, info, bundles) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoPriorityEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoPriorityEnabled {.env = env, .asyncWork = nullptr, .bundles = bundles};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getPriorityEnabledByBundles", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Napi get priorityEnable by bundles work excute.");
            AsyncCallbackInfoPriorityEnabled *asynccallbackinfo =
                static_cast<AsyncCallbackInfoPriorityEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetPriorityEnabledByBundles(
                    asynccallbackinfo->bundles, asynccallbackinfo->priorityEnable);
            }
        },
        AsyncCompleteCallbackNapiGetPriorityEnabledByBundles,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value ParseParametersForSetPriorityEnable(const napi_env& env, const napi_callback_info& info,
    std::map<sptr<NotificationBundleOption>, bool> &params)
{
    ANS_LOGD("ParseParameters priorityEnable");
    size_t argc = SET_PRIORITY_ENABLE_MAX_PARA;
    napi_value argv[SET_PRIORITY_ENABLE_MAX_PARA] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc != SET_PRIORITY_ENABLE_MAX_PARA) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_value entriesFn = nullptr;
    napi_value iter = nullptr;
    napi_value nextFn = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, argv[PARAM0], "entries", &entriesFn));
    NAPI_CALL(env, napi_call_function(env, argv[PARAM0], entriesFn, 0, nullptr, &iter));
    NAPI_CALL(env, napi_get_named_property(env, iter, "next", &nextFn));

    bool done = false;
    while (!done) {
        napi_value resultObj;
        NAPI_CALL(env, napi_call_function(env, iter, nextFn, 0, nullptr, &resultObj));

        napi_value doneVal;
        NAPI_CALL(env, napi_get_named_property(env, resultObj, "done", &doneVal));

        NAPI_CALL(env, napi_get_value_bool(env, doneVal, &done));
        if (done) {
            break;
        }

        napi_value pairArr;
        NAPI_CALL(env, napi_get_named_property(env, resultObj, "value", &pairArr));
        napi_value jsKey = nullptr;
        napi_value jsVal = nullptr;
        NAPI_CALL(env, napi_get_element(env, pairArr, 0, &jsKey));
        NAPI_CALL(env, napi_get_element(env, pairArr, 1, &jsVal));
        NotificationBundleOption bundle;
        if (!Common::GetBundleOption(env, jsKey, bundle)) {
            std::string msg = "Invalid bundleOption in map.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        bool enable = false;
        NAPI_CALL(env, napi_get_value_bool(env, jsVal, &enable));
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(bundle);
        if (bo == nullptr) {
            Common::NapiThrow(env, ERROR_NO_MEMORY);
            return nullptr;
        }
        params[bo] = enable;
    }
    return Common::NapiGetNull(env);
}

napi_value NapiSetPriorityEnabledByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiSetPriorityEnabledByBundles");
    std::map<sptr<NotificationBundleOption>, bool> params;
    if (ParseParametersForSetPriorityEnable(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoPriorityEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoPriorityEnabled {
        .env = env, .asyncWork = nullptr, .priorityEnable = std::move(params)};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setPriorityEnabledByBundles", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetPriorityEnabledByBundles work execute.");
            AsyncCallbackInfoPriorityEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoPriorityEnabled *>(data);
            if (asynccallbackinfo != nullptr) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetPriorityEnabledByBundles(
                    asynccallbackinfo->priorityEnable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfoPriorityEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoPriorityEnabled *>(data);
            if (asynccallbackinfo != nullptr) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
                ANS_LOGD("NapiSetPriorityEnabledByBundles work complete end.");
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS