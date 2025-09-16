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

napi_value GetNotificationExtensionSubscriptionInfo(
    const napi_env& env, const napi_value& value, sptr<NotificationExtensionSubscriptionInfo>& info)
{
    ANS_LOGD("called");

    if (info == nullptr) {
        ANS_LOGW("Invalid NotificationExtensionSubscriptionInfo object ptr.");
        return nullptr;
    }

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    
    // addr: string
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_named_property(env, value, "addr", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. string expected.");
        std::string msg = "Incorrect parameter addr. The type of addr must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    info->SetAddr(str);

    // type: SubscribeType
    int32_t type = 0;
    napi_get_named_property(env, value, "type", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. number expected.");
        std::string msg = "Incorrect parameter uid. The type of uid must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &type);
    NotificationConstant::SubscribeType outType = NotificationConstant::SubscribeType::BLUETOOTH;
    if (!AnsEnumUtil::SubscribeTypeJSToC(SubscribeType(type), outType)) {
        std::string msg = "Incorrect parameter types. SubscribeType name must be in enum.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    info->SetType(outType);

    return Common::NapiGetNull(env);
}

napi_value SetNotificationExtensionSubscriptionInfo(
    const napi_env& env, const sptr<NotificationExtensionSubscriptionInfo>& info, napi_value& result)
{
    if (info == nullptr) {
        ANS_LOGW("Invalid NotificationExtensionSubscriptionInfo object ptr.");
        return nullptr;
    }

    napi_value value = nullptr;

    // addr: string
    napi_create_string_utf8(env, info->GetAddr().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "addr", value);

    // type: SubscribeType
    SubscribeType outType = SubscribeType::BLUETOOTH;
    if (!AnsEnumUtil::SubscribeTypeCToJS(info->GetType(), outType)) {
        return nullptr;
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "type", value);

    return result;
}

napi_value ParseParameters(const napi_env& env, const napi_callback_info& info,
    std::vector<sptr<NotificationExtensionSubscriptionInfo>>& subscriptionInfo)
{
    ANS_LOGD("called");
    size_t argc = SUBSCRIBE_MAX_PARA;
    napi_value argv[SUBSCRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SUBSCRIBE_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (!isArray) {
        ANS_LOGE("Wrong argument type. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    uint32_t length = 0;
    napi_get_array_length(env, argv[PARAM0], &length);
    if (length == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    for (size_t index = 0; index < length; index++) {
        napi_value nNotificationExtensionSubscriptionInfo = nullptr;
        napi_get_element(env, argv[PARAM0], index, &nNotificationExtensionSubscriptionInfo);
        NAPI_CALL_BASE(env, napi_typeof(env, nNotificationExtensionSubscriptionInfo, &valuetype), nullptr);
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        sptr<NotificationExtensionSubscriptionInfo> item =
            new (std::nothrow) NotificationExtensionSubscriptionInfo();
        if (item == nullptr) {
            ANS_LOGE("Failed to create NotificationExtensionSubscriptionInfo.");
            std::string msg =
                "Parameter verification failed. Failed to create NotificationExtensionSubscriptionInfo ptr";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto retValue = GetNotificationExtensionSubscriptionInfo(
            env, nNotificationExtensionSubscriptionInfo, item);
        if (retValue == nullptr) {
            ANS_LOGE("null retValue");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        subscriptionInfo.emplace_back(item);
    }
    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackSubscriptionReturnVoid(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoNotificationExtensionSubscription* asynccallbackinfo =
        static_cast<AsyncCallbackInfoNotificationExtensionSubscription*>(data);
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

void AsyncCompleteCallbackReturnSubscribeInfoArray(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoNotificationExtensionSubscription* asynccallbackinfo =
        static_cast<AsyncCallbackInfoNotificationExtensionSubscription*>(data);
    if (!asynccallbackinfo) {
        ANS_LOGW("Invalid asynccallbackinfo ptr.");
        return;
    }
    napi_value result = nullptr;
    if (asynccallbackinfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    } else {
        napi_value arr = nullptr;
        int32_t count = 0;
        napi_create_array(env, &arr);
        for (auto item : asynccallbackinfo->subscriptionInfo) {
            if (item == nullptr) {
                ANS_LOGW("Invalid NotificationExtensionSubscriptionInfo object ptr.");
                continue;
            }
            napi_value notificationExtensionSubscriptionInfo = nullptr;
            napi_create_object(env, &notificationExtensionSubscriptionInfo);
            if (!SetNotificationExtensionSubscriptionInfo(env, item, notificationExtensionSubscriptionInfo)) {
                ANS_LOGW("Set NotificationExtensionSubscriptionInfo object failed.");
                continue;
            }
            napi_set_element(env, arr, count, notificationExtensionSubscriptionInfo);
            ++count;
        }
        ANS_LOGI("count = %{public}d", count);
        result = arr;
        if ((count == 0) && (asynccallbackinfo->subscriptionInfo.size() > 0)) {
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

napi_value NapiNotificationExtensionSubscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionSubscription* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionSubscription { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    if (ParseParameters(env, info, asynccallbackinfo->subscriptionInfo) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "notificationExtensionSubscribe", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("notificationExtensionSubscribe work excute.");
            AsyncCallbackInfoNotificationExtensionSubscription *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionSubscription *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::NotificationExtensionSubscribe(asynccallbackinfo->subscriptionInfo);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackSubscriptionReturnVoid,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiNotificationExtensionUnsubscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionSubscription* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionSubscription { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "notificationExtensionUnsubscribe", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("notificationExtensionUnsubscribe work excute.");
            AsyncCallbackInfoNotificationExtensionSubscription *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionSubscription *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::NotificationExtensionUnsubscribe();
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackSubscriptionReturnVoid,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

napi_value NapiGetSubscribeInfo(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionSubscription* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionSubscription { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSubscribeInfo", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("getSubscribeInfo work excute.");
            AsyncCallbackInfoNotificationExtensionSubscription *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionSubscription *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetSubscribeInfo(asynccallbackinfo->subscriptionInfo);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackReturnSubscribeInfoArray,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
