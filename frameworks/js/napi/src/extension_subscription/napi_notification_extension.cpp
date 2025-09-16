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


napi_value ParseParametersForGetUserGrantedEnableBundle(const napi_env& env, const napi_callback_info& info,
    NotificationExtensionUserGrantedParams& params, bool& isForSelf)
{
    isForSelf = false;
    size_t argc = NAPI_GET_USER_GRANTED_ENABLE_BUNDLES_MAX_PARA;
    napi_value argv[NAPI_GET_USER_GRANTED_ENABLE_BUNDLES_MAX_PARA] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc < NAPI_GET_USER_GRANTED_ENABLE_BUNDLES_MAX_PARA) {
        isForSelf = true;
        return Common::NapiGetNull(env);
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

napi_value ParseParametersForSetUserGrantedBundleState(const napi_env& env, const napi_callback_info& info,
    NotificationExtensionUserGrantedParams& params)
{
    ANS_LOGD("called");
    
    size_t argc = NAPI_SET_USER_GRANTED_BUNDLE_STATE_MAX_PARA;
    napi_value argv[NAPI_SET_USER_GRANTED_BUNDLE_STATE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < NAPI_SET_USER_GRANTED_BUNDLE_STATE_MAX_PARA) {
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

    // argv[1]: enabledBundles
    bool isArray = false;
    napi_is_array(env, argv[PARAM1], &isArray);
    if (!isArray) {
        ANS_LOGE("Wrong argument type. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    uint32_t length = 0;
    napi_get_array_length(env, argv[PARAM1], &length);
    if (length == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    for (size_t index = 0; index < length; index++) {
        napi_value bundle = nullptr;
        napi_get_element(env, argv[PARAM1], index, &bundle);
        NAPI_CALL_BASE(env, napi_typeof(env, bundle, &valuetype), nullptr);
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        sptr<NotificationBundleOption> item = new (std::nothrow) NotificationBundleOption();
        if (item == nullptr) {
            ANS_LOGE("Failed to create NotificationBundleOption.");
            std::string msg = "Parameter verification failed. Failed to create NotificationBundleOption ptr";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto retValue = Common::GetBundleOption(env, bundle, *item);
        if (retValue == nullptr) {
            ANS_LOGE("null retValue");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        params.bundles.emplace_back(item);
    }

    // argv[2]: enabled
    NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM2], &params.enabled);

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

void AsyncCompleteCallbackRetrunBundleOptionArray(napi_env env, napi_status status, void *data)
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
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto item : asynccallbackinfo->params.bundles) {
                if (item == nullptr) {
                    ANS_LOGW("Invalid NotificationBundleOption object ptr.");
                    continue;
                }
                napi_value bundleOption = nullptr;
                napi_create_object(env, &bundleOption);
                if (!Common::SetBundleOption(env, *item, bundleOption)) {
                    ANS_LOGW("Set NotificationBundleOption object failed.");
                    continue;
                }
                napi_set_element(env, arr, count, bundleOption);
                ++count;
            }
            ANS_LOGI("count = %{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->params.bundles.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetUserGrantedEnableBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    bool isForSelf = false;
    if (ParseParametersForGetUserGrantedEnableBundle(env, info, asynccallbackinfo->params, isForSelf) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getUserGrantedEnableBundles", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    if (isForSelf) {
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ANS_LOGD("getUserGrantedEnableBundles work excute.");
                AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                    static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
                if (asynccallbackinfo) {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::GetUserGrantedEnabledBundlesForSelf(asynccallbackinfo->params.bundles);
                    ANS_LOGI("GetUserGrantedEnabledBundles errorCode = %{public}d", asynccallbackinfo->info.errorCode);
                }
            },
            AsyncCompleteCallbackRetrunBundleOptionArray,
            (void *)asynccallbackinfo,
            &asynccallbackinfo->asyncWork);
    } else {
        napi_create_async_work(env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                ANS_LOGD("getUserGrantedEnableBundles work excute.");
                AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                    static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
                if (asynccallbackinfo) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetUserGrantedEnabledBundles(
                        asynccallbackinfo->params.targetBundle, asynccallbackinfo->params.bundles);
                    ANS_LOGI("GetUserGrantedEnabledBundles errorCode = %{public}d", asynccallbackinfo->info.errorCode);
                }
            },
            AsyncCompleteCallbackRetrunBundleOptionArray,
            (void *)asynccallbackinfo,
            &asynccallbackinfo->asyncWork);
    }

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiSetUserGrantedBundleState(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    if (ParseParametersForSetUserGrantedBundleState(env, info, asynccallbackinfo->params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setUserGrantedBundleState", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("setUserGrantedBundleState work excute.");
            AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::SetUserGrantedBundleState(asynccallbackinfo->params.targetBundle,
                        asynccallbackinfo->params.bundles, asynccallbackinfo->params.enabled);
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
