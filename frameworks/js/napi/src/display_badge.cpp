/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "display_badge.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int ENABLE_BADGE_DISPLAYED_MAX_PARA = 3;
const int ENABLE_BADGE_DISPLAYED_MIN_PARA = 2;
const int IS_DISPLAY_BADGE_MAX_PARA = 2;
const int IS_DISPLAY_BADGE_MIN_PARA = 1;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnableBadgeParams &params)
{
    ANS_LOGD("called");

    size_t argc = ENABLE_BADGE_DISPLAYED_MAX_PARA;
    napi_value argv[ENABLE_BADGE_DISPLAYED_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLE_BADGE_DISPLAYED_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("null retValue");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM1], &params.enable);

    // argv[2]:callback
    if (argc >= ENABLE_BADGE_DISPLAYED_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsDisplayBadgeParams &params)
{
    ANS_LOGD("called");

    size_t argc = IS_DISPLAY_BADGE_MAX_PARA;
    napi_value argv[IS_DISPLAY_BADGE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc < IS_DISPLAY_BADGE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle / callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));

    if ((valuetype != napi_function) && (valuetype != napi_object)) {
        ANS_LOGE("Wrong argument type. Function or object expected, %{public}d", valuetype);
        std::string msg = "Incorrect parameter types.The type of param must be function or object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (valuetype == napi_object) {
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
        if (retValue == nullptr) {
            ANS_LOGE("null retValue");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        params.hasBundleOption = true;
    } else {
        napi_create_reference(env, argv[PARAM0], 1, &params.callback);
    }

    // argv[1]:callback
    if (argc >= IS_DISPLAY_BADGE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value DisplayBadge(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    EnableBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnableBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnableBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create DisplayBadge string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "DisplayBadge", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("DisplayBadge work excute.");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("option.bundle : %{public}s option.uid : %{public}d enable = %{public}d",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.enable);
                asynccallbackinfo->info.errorCode = NotificationHelper::SetShowBadgeEnabledForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
                ANS_LOGI("errorCode : %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("DisplayBadge work complete.");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete DisplayBadge callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("DisplayBadge work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackIsBadgeDisplayed(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }
    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->enabled, &result);
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value IsBadgeDisplayed(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    IsDisplayBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGE("Parse params fail!");
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsDisplayBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create IsBadgeDisplayed string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsBadgeDisplayed", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("IsBadgeDisplayed work excute.");
            AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGI("option.bundle : %{public}s option.uid : %{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid());
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabledForBundle(
                        asynccallbackinfo->params.option, asynccallbackinfo->enabled);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabled(
                        asynccallbackinfo->enabled);
                }
                ANS_LOGI("errorCode : %{public}d, enabled : %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->enabled);
            }
        },
        AsyncCompleteCallbackIsBadgeDisplayed,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
