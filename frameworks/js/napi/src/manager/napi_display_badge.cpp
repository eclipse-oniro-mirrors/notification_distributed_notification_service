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

#include "napi_display_badge.h"

#include "ans_inner_errors.h"
#include "display_badge.h"

namespace OHOS {
namespace NotificationNapi {
const int32_t SET_BADGE_NUMBER_MAX_PARA = 2;
const int32_t SET_BADGE_NUMBER_MIN_PARA = 1;
const int32_t SET_BADGE_NUMBER_BY_BUNDLE_PARA = 2;

napi_value NapiDisplayBadge(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    EnableBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnableBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnableBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "DisplayBadge", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiDisplayBadge work excute.");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("option.bundle = %{public}s option.uid = %{public}d enable = %{public}d",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.enable);
                asynccallbackinfo->info.errorCode = NotificationHelper::SetShowBadgeEnabledForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiDisplayBadge work complete.");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiDisplayBadge callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiDisplayBadge work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiDisplayBadge callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiIsBadgeDisplayed(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->enabled, &result);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsBadgeDisplayed(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    IsDisplayBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGE("Failed to parse params!");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsDisplayBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsBadgeDisplayed", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsBadgeDisplayed work excute.");
            AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGI("option.bundle = %{public}s option.uid = %{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid());
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabledForBundle(
                        asynccallbackinfo->params.option, asynccallbackinfo->enabled);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabled(
                        asynccallbackinfo->enabled);
                }
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d, enabled = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->enabled);
            }
        },
        AsyncCompleteCallbackNapiIsBadgeDisplayed,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiIsBadgeDisplayed callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, SetBadgeNumberParams &params)
{
    ANS_LOGD("enter");

    size_t argc = SET_BADGE_NUMBER_MAX_PARA;
    napi_value argv[SET_BADGE_NUMBER_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_BADGE_NUMBER_MIN_PARA) {
        ANS_LOGW("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: badgeNumber or bundleOption
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    // case1: setBadgeNumberByBundle(bundleOption, badgeNumber)
    if (valuetype == napi_object) {
        if (argc != SET_BADGE_NUMBER_BY_BUNDLE_PARA) {
            ANS_LOGE("Wrong number of arguments. Expect exactly two.");
            std::string msg = "Mandatory parameters are left unspecified. Expect exactly two.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        Common::GetBundleOption(env, argv[PARAM0], params.option);
        // argv[1]: badgeNumber
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, argv[PARAM1], &params.badgeNumber);
        return Common::NapiGetNull(env);
    }
    // case2: setBadgeNumber(badgeNumber)
    if (valuetype != napi_number) {
        ANS_LOGW("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, argv[PARAM0], &params.badgeNumber);

    // argv[1]:callback
    if (argc >= SET_BADGE_NUMBER_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiSetBadgeNumber(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackSetBadgeNumber *asynccallbackinfo = static_cast<AsyncCallbackSetBadgeNumber *>(data);
    Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
    if (asynccallbackinfo->info.callback != nullptr) {
        napi_delete_reference(env, asynccallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
}

napi_value NapiSetBadgeNumber(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    SetBadgeNumberParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackSetBadgeNumber *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackSetBadgeNumber {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setBadgeNumber", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetBadgeNumber work excute.");
            AsyncCallbackSetBadgeNumber *asynccallbackinfo = static_cast<AsyncCallbackSetBadgeNumber *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("option.badgeNumber: %{public}d", asynccallbackinfo->params.badgeNumber);
                std::string instanceKey = Common::GetAppInstanceKey();
                asynccallbackinfo->info.errorCode = NotificationHelper::SetBadgeNumber(
                    asynccallbackinfo->params.badgeNumber, instanceKey);
            }
        },
        AsyncCompleteCallbackNapiSetBadgeNumber,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiSetBadgeNumber callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetBadgeNumberByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("Enter.");
    SetBadgeNumberParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackSetBadgeNumber *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackSetBadgeNumber {.env = env, .asyncWork = nullptr, .params = params};
    if (asyncCallbackInfo == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return Common::NapiGetUndefined(env);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setBadgeNumberByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Napi set badge number by bundle work execute.");
            AsyncCallbackSetBadgeNumber *asyncCallbackInfo = static_cast<AsyncCallbackSetBadgeNumber *>(data);
            if (asyncCallbackInfo) {
                ANS_LOGI("Option.bundle = %{public}s, option.uid = %{public}d, badge number = %{public}d.",
                    asyncCallbackInfo->params.option.GetBundleName().c_str(),
                    asyncCallbackInfo->params.option.GetUid(),
                    asyncCallbackInfo->params.badgeNumber);
                asyncCallbackInfo->info.errorCode = NotificationHelper::SetBadgeNumberByBundle(
                    asyncCallbackInfo->params.option, asyncCallbackInfo->params.badgeNumber);
            }
        },
        AsyncCompleteCallbackNapiSetBadgeNumber,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    bool isCallback = asyncCallbackInfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("Callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
