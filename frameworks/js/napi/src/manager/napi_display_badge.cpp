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
    ANS_LOGD("called");
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
                
                asynccallbackinfo->info.errorCode = NotificationHelper::SetShowBadgeEnabledForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
                ANS_LOGI("displayBadge bundle=%{public}s uid=%{public}d enable=%{public}d code=%{public}d",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.enable, asynccallbackinfo->info.errorCode);
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
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiIsBadgeDisplayed(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
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
    ANS_LOGD("called");
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
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabledForBundle(
                        asynccallbackinfo->params.option, asynccallbackinfo->enabled);
                    ANS_LOGI("get badgeEnabled bundle:%{public}s,uid:%{public}d,code:%{public}d,enabled:%{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid(),
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->enabled);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabled(
                        asynccallbackinfo->enabled);
                    ANS_LOGI("get badgeEnabled code:%{public}d,enabled:%{public}d",
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->enabled);
                }
            }
        },
        AsyncCompleteCallbackNapiIsBadgeDisplayed,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, SetBadgeNumberParams &params)
{
    ANS_LOGD("called");

    size_t argc = SET_BADGE_NUMBER_MAX_PARA;
    napi_value argv[SET_BADGE_NUMBER_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_BADGE_NUMBER_MIN_PARA) {
        ANS_LOGD("Wrong number of arguments.");
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
        ANS_LOGD("Wrong argument type. Number expected.");
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
    ANS_LOGD("called");
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
    ANS_LOGD("called");
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
                ANS_LOGI("setBadge number:%{public}d", asynccallbackinfo->params.badgeNumber);
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
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetBadgeNumberByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
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
                ANS_LOGI("setBadge bundle=%{public}s uid=%{public}d badge=%{public}d",
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
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParametersForGetBadges(const napi_env& env, const napi_callback_info& info,
    std::vector<NotificationBundleOption> &bundles)
{
    size_t argc = SET_BADGE_NUMBER_MIN_PARA;
    napi_value argv[SET_BADGE_NUMBER_MIN_PARA] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    if (argc < SET_BADGE_NUMBER_MIN_PARA) {
        ANS_LOGE("Missing parameter.");
        std::string msg = "Missing parameter.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, argv[PARAM0], &isArray));
    if (!isArray) {
        ANS_LOGE("Argument 0 must be an array of BundleOption.");
        std::string msg = "Argument 0 must be an array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    uint32_t length = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[PARAM0], &length));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        NAPI_CALL(env, napi_get_element(env, argv[PARAM0], i, &item));
        NotificationBundleOption option;
        if (!Common::GetBundleOption(env, item, option)) {
            ANS_LOGE("Invalid BundleOption at index %u", i);
            std::string msg = "Invalid BundleOption in array.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        bundles.push_back(std::move(option));
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParametersForSetBadges(const napi_env& env, const napi_callback_info& info,
    std::vector<std::pair<NotificationBundleOption, bool>> &bundles)
{
    size_t argc = SET_BADGE_NUMBER_MIN_PARA;
    napi_value argv[SET_BADGE_NUMBER_MIN_PARA] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    if (argc < SET_BADGE_NUMBER_MIN_PARA) {
        ANS_LOGE("Missing parameter.");
        std::string msg = "Missing parameter.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
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
        NotificationBundleOption option;
        if (!Common::GetBundleOption(env, jsKey, option)) {
            ANS_LOGE("Invalid BundleOption in map.");
            std::string msg = "Invalid BundleOption in map.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        bool enable = false;
        NAPI_CALL(env, napi_get_value_bool(env, jsVal, &enable));
        bundles.push_back(std::make_pair(std::move(option), enable));
    }
    return Common::NapiGetNull(env);
}

napi_value NapiSetBadgeDisplayStatusByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    std::vector<std::pair<NotificationBundleOption, bool>> params;
    if (ParseParametersForSetBadges(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoBatchSetBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoBatchSetBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::NapiGetUndefined(env);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setBadgeDisplayStatusByBundles", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetBadgeDisplayStatusByBundles work execute.");
            AsyncCallbackInfoBatchSetBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoBatchSetBadge *>(data);
            if (asynccallbackinfo != nullptr) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetShowBadgeEnabledForBundles(
                    asynccallbackinfo->params);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiDisplayBadge work complete.");
            AsyncCallbackInfoBatchSetBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoBatchSetBadge *>(data);
            if (asynccallbackinfo != nullptr) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
                ANS_LOGD("NapiDisplayBadge work complete end.");
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackBatchGetBadge(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackBatchGetBadge work complete.");
    AsyncCallbackInfoBatchGetBadge *asyncCallbackInfo = static_cast<AsyncCallbackInfoBatchGetBadge *>(data);
    if (asyncCallbackInfo) {
        napi_value resultMap;
        napi_create_map(env, &resultMap);
        
        for (auto itr = asyncCallbackInfo->bundleEnable.begin(); itr != asyncCallbackInfo->bundleEnable.end(); ++itr) {
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
        if (asyncCallbackInfo->bundleEnable.empty()) {
            ANS_LOGW("No bundleEnable found for the provided bundles.");
            resultMap  = Common::NapiGetNull(env);
        }

        Common::CreateReturnValue(env, asyncCallbackInfo->info, resultMap);
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        asyncCallbackInfo = nullptr;
    }
}

napi_value NapiGetBadgeDisplayStatusByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiGetBadgeDisplayStatusByBundles called");
    std::vector<NotificationBundleOption> params;
    if (ParseParametersForGetBadges(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoBatchGetBadge *asyncCallbackInfo =
        new (std::nothrow) AsyncCallbackInfoBatchGetBadge{
            .env = env, .asyncWork = nullptr, .bundles = std::move(params)};
    if (!asyncCallbackInfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asyncCallbackInfo->info, promise);
    asyncCallbackInfo->info.isCallback = false;

    napi_value resourceName;
    napi_create_string_latin1(env, "getBadgeDisplayStatusByBundles", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetBadgeDisplayStatusByBundles work excute.");
            AsyncCallbackInfoBatchGetBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoBatchGetBadge *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabledForBundles(
                    asynccallbackinfo->bundles, asynccallbackinfo->bundleEnable);
            }
        },
        AsyncCompleteCallbackBatchGetBadge,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);

    napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

void AsyncCompleteCallbackNapiGetBadgeNumber(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiGetBadgeNumber");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackGetBadgeNumber *asynccallbackinfo = static_cast<AsyncCallbackGetBadgeNumber*>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    napi_value result = nullptr;
    if (asynccallbackinfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    } else {
        napi_create_int32(env, asynccallbackinfo->badgeNumber, &result);
    }
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

napi_value NapiGetBadgeNumber(napi_env env, napi_callback_info info)
{
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackGetBadgeNumber {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getBadgeNumber", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetBadgeNumber word excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackGetBadgeNumber *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetBadgeNumber(asynccallbackinfo->badgeNumber);
            }
        },
        AsyncCompleteCallbackNapiGetBadgeNumber,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
