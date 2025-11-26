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

#include "enable_notification.h"

#include <uv.h>

#include "ability_manager_client.h"

#include "ans_dialog_host_client.h"
#include "ans_inner_errors.h"
#include "js_ans_dialog_callback.h"

namespace OHOS {
namespace NotificationNapi {
const int ENABLE_NOTIFICATION_MAX_PARA = 3;
const int ENABLE_NOTIFICATION_MIN_PARA = 2;
const int IS_NOTIFICATION_ENABLE_MAX_PARA = 2;
const int GET_BUNDLE_MAX_PARAM = 1;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnableParams &params)
{
    ANS_LOGD("enter");

    size_t argc = ENABLE_NOTIFICATION_MAX_PARA;
    napi_value argv[ENABLE_NOTIFICATION_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLE_NOTIFICATION_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Parameter type error. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
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
    if (argc >= ENABLE_NOTIFICATION_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsEnableParams &params)
{
    ANS_LOGD("enter");

    size_t argc = IS_NOTIFICATION_ENABLE_MAX_PARA;
    napi_value argv[IS_NOTIFICATION_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc == 0) {
        return Common::NapiGetNull(env);
    }

    // argv[0]: bundle / userId / callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if ((valuetype != napi_object) && (valuetype != napi_number) && (valuetype != napi_function)) {
        ANS_LOGE("Parameter type error. Function or object expected. Excute promise.");
        return Common::NapiGetNull(env);
    }
    if (valuetype == napi_object) {
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        params.hasBundleOption = true;
    } else if (valuetype == napi_number) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
        params.hasUserId = true;
    } else {
        napi_create_reference(env, argv[PARAM0], 1, &params.callback);
    }

    // argv[1]:callback
    if (argc >= IS_NOTIFICATION_ENABLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

bool ParseUserIdParameters(const napi_env &env, const napi_callback_info &info, int32_t &userId)
{
    size_t argc = GET_BUNDLE_MAX_PARAM;
    napi_value argv[GET_BUNDLE_MAX_PARAM] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL), false);
    if (argc == GET_BUNDLE_MAX_PARAM) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valuetype), false);
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return false;
        }
        NAPI_CALL_BASE(env, napi_get_value_int32(env, argv[PARAM0], &userId), false);
    }
    return true;
}

void AsyncCompleteCallbackEnableNotification(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
    if (asynccallbackinfo) {
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete EnableNotification callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value EnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    EnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create enableNotification string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("EnableNotification work excute.");
            AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
            if (asynccallbackinfo) {
                std::string deviceId {""};
                asynccallbackinfo->info.errorCode = NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(
                    asynccallbackinfo->params.option, deviceId, asynccallbackinfo->params.enable);
                ANS_LOGI("setEnableNotification code=%{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackEnableNotification,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("enableNotification callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackIsNotificationEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->allowed, &result);
        if (asynccallbackinfo->newInterface) {
            Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        } else {
            Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        }
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value IsNotificationEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Failed to create asynccallbackinfo.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create isNotificationEnabled string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isNotificationEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("IsNotificationEnabled work excute.");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.option, asynccallbackinfo->allowed);
                    ANS_LOGI("isNotificationEnabled bundle:%{public}s,uid:%{public}d,"
                        "code=%{public}d,allowed=%{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid(),
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
                } else if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.userId, asynccallbackinfo->allowed);
                    ANS_LOGI("isNotificationEnabled userId=%{public}d,code=%{public}d,allowed=%{public}d",
                        asynccallbackinfo->params.userId,
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->allowed);
                    ANS_LOGI("isNotificationEnabled code=%{public}d,allowed=%{public}d",
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
                }
            }
        },
        AsyncCompleteCallbackIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("isNotificationEnabled callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value IsNotificationEnabledSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo fail.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create IsNotificationEnabledSelf string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsNotificationEnabledSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("IsNotificationEnabledSelf work excute.");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGE("Not allowed to query another application.");
                } else {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::IsAllowedNotifySelf(asynccallbackinfo->allowed);
                }
                ANS_LOGI("isNotificationEnabledSelf code=%{public}d,allowed=%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("isNotificationEnabledSelf callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackRequestEnableNotification(napi_env env, void *data)
{
    ANS_LOGD("enter");
    if (data == nullptr) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (asynccallbackinfo->newInterface) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    } else {
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
    }
    if (asynccallbackinfo->info.callback != nullptr) {
        napi_delete_reference(env, asynccallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
}

napi_value RequestEnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};

    if (!asynccallbackinfo) {
        ANS_LOGD("Failed to create asynccallbackinfo.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "RequestEnableNotification", NAPI_AUTO_LENGTH, &resourceName);

    auto ipcCall = [](napi_env env, void* data) {
        ANS_LOGD("enter");
        if (data == nullptr) {
            ANS_LOGE("data is invalid");
            return;
        }
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
        std::string deviceId {""};
        sptr<AnsDialogHostClient> client = nullptr;
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            asynccallbackinfo->info.errorCode = ERR_ANS_DIALOG_IS_POPPING;
            return;
        }
        asynccallbackinfo->info.errorCode =
            NotificationHelper::RequestEnableNotification(deviceId, client,
                asynccallbackinfo->params.callerToken);
        ANS_LOGI("request enableNotification code:%{public}d", asynccallbackinfo->info.errorCode);
    };
    auto jsCb = [](napi_env env, napi_status status, void* data) {
        ANS_LOGD("enter");
        if (data == nullptr) {
            AnsDialogHostClient::Destroy();
            return;
        }
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
        ErrCode errCode = asynccallbackinfo->info.errorCode;
        if (errCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
            ANS_LOGE("poped error,code:%{public}d", errCode);
            AnsDialogHostClient::Destroy();
            AsyncCompleteCallbackRequestEnableNotification(env, static_cast<void*>(asynccallbackinfo));
            return;
        }
        // Dialog is popped
        auto jsCallback = std::make_unique<JsAnsDialogCallback>();
        if (!jsCallback->Init(env, asynccallbackinfo, AsyncCompleteCallbackRequestEnableNotification) ||
            !AnsDialogHostClient::SetDialogCallbackInterface(std::move(jsCallback))
        ) {
            ANS_LOGE("set dialogCallbackInterface error");
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
            AnsDialogHostClient::Destroy();
            AsyncCompleteCallbackRequestEnableNotification(env, static_cast<void*>(asynccallbackinfo));
            return;
        }
    };

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        ipcCall,
        jsCb,
        static_cast<void*>(asynccallbackinfo),
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("RequestEnableNotification callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

}  // namespace NotificationNapi
}  // namespace OHOS
