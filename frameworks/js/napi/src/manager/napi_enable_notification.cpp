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

#include "napi_enable_notification.h"

#include "napi_base_context.h"

#include "ans_dialog_host_client.h"
#include "ans_inner_errors.h"
#include "enable_notification.h"
#include "js_ans_dialog_callback.h"

namespace OHOS {
namespace NotificationNapi {
const int IS_NOTIFICATION_ENABLE_MAX_PARA = 2;
void AsyncCompleteCallbackNapiEnableNotification(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiEnableNotification callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiEnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    EnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiEnableNotification work excute.");
            AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
            if (asynccallbackinfo) {
                std::string deviceId {""};
                asynccallbackinfo->info.errorCode = NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(
                    asynccallbackinfo->params.option, deviceId, asynccallbackinfo->params.enable);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiEnableNotification,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiEnableNotification callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiIsNotificationEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->allowed, &result);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

__attribute__((no_sanitize("cfi"))) napi_value NapiIsNotificationEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGD("ParseParameters is nullptr.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isNotificationEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsNotificationEnabled work excute.");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGI("option.bundle : %{public}s option.uid : %{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid());
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.option, asynccallbackinfo->allowed);
                } else if (asynccallbackinfo->params.hasUserId) {
                    ANS_LOGI("userId : %{public}d", asynccallbackinfo->params.userId);
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.userId, asynccallbackinfo->allowed);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotifySelf(
                        asynccallbackinfo->allowed);
                }
                ANS_LOGI("asynccallbackinfo->info.errorCode : %{public}d, allowed : %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackNapiIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiIsNotificationEnabled callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiIsNotificationEnabledSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is null.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsNotificationEnabledSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsNotificationEnabledSelf work excute.");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGE("Not allowed to query another application");
                } else {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::IsAllowedNotifySelf(asynccallbackinfo->allowed);
                }
                ANS_LOGD("asynccallbackinfo->info.errorCode = %{public}d, allowed = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackNapiIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiIsNotificationEnabledSelf callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void NapiAsyncCompleteCallbackRequestEnableNotification(napi_env env, void *data)
{
    ANS_LOGD("enter");
    if (data == nullptr) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    if (asynccallbackinfo->info.callback != nullptr) {
        napi_delete_reference(env, asynccallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
}

napi_value NapiRequestEnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    IsEnableParams params {};
    if (ParseRequestEnableParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnable {
            .env = env, .params = params, .newInterface = true};
    if (!asynccallbackinfo) {
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
        ANS_LOGI("done, code is %{public}d.", asynccallbackinfo->info.errorCode);
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
            ANS_LOGE("error, code is %{public}d.", errCode);
            AnsDialogHostClient::Destroy();
            NapiAsyncCompleteCallbackRequestEnableNotification(env, static_cast<void*>(asynccallbackinfo));
            return;
        }
        // Dialog is popped
        auto jsCallback = std::make_unique<JsAnsDialogCallback>();
        if (!jsCallback->Init(env, asynccallbackinfo, NapiAsyncCompleteCallbackRequestEnableNotification) ||
            !AnsDialogHostClient::SetDialogCallbackInterface(std::move(jsCallback))
        ) {
            ANS_LOGE("error");
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
            AnsDialogHostClient::Destroy();
            NapiAsyncCompleteCallbackRequestEnableNotification(env, static_cast<void*>(asynccallbackinfo));
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

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiRequestEnableNotification callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseRequestEnableParameters(const napi_env &env, const napi_callback_info &info, IsEnableParams &params)
{
    ANS_LOGD("enter");

    size_t argc = IS_NOTIFICATION_ENABLE_MAX_PARA;
    napi_value argv[IS_NOTIFICATION_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc == 0) {
        return Common::NapiGetNull(env);
    }

    // argv[0]: context / callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if ((valuetype != napi_object) && (valuetype != napi_function)) {
        ANS_LOGW("Wrong argument type. Function or object expected. Excute promise.");
        return Common::NapiGetNull(env);
    }
    if (valuetype == napi_object) {
        bool stageMode = false;
        napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[PARAM0], stageMode);
        if (status == napi_ok && stageMode) {
            auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[PARAM0]);
            sptr<IRemoteObject> callerToken = context->GetToken();
            params.callerToken = callerToken;
            params.hasCallerToken = true;
        } else {
            ANS_LOGE("Only support stage mode");
            std::string msg = "Incorrect parameter types.Only support stage mode.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
    } else {
        napi_create_reference(env, argv[PARAM0], 1, &params.callback);
    }
    // argv[1]:context
    if (argc >= IS_NOTIFICATION_ENABLE_MAX_PARA && valuetype == napi_object) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiGetAllNotificationEnableStatus(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("Called.");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    napi_value result = nullptr;
    AsyncCallbackInfoEnableStatus *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableStatus *>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("asynccallbackinfo is nullptr");
        return;
    }
    if (asynccallbackinfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    }
    napi_value arr = nullptr;
    napi_create_array(env, &arr);
    size_t count = 0;
    for (auto vec : asynccallbackinfo->bundleOptionVector) {
        napi_value nSlot = nullptr;
        napi_create_object(env, &nSlot);
        Common::SetNotificationEnableStatus(env, vec, nSlot);
        napi_set_element(env, arr, count, nSlot);
        count++;
    }
    result = arr;
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    if (asynccallbackinfo->info.callback != nullptr) {
        ANS_LOGD("Delete napiGetSlots callback reference.");
        napi_delete_reference(env, asynccallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
}

napi_value NapiGetAllNotificationEnabledBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("Called");
    napi_ref callback = nullptr;
    AsyncCallbackInfoEnableStatus *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnableStatus{ .env = env, .asyncWork = nullptr };
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("asynccallbackinfo is nullptr");
        return Common::NapiGetUndefined(env);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllNotificationEnabledBundles", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncCallbackInfoEnableStatus *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableStatus *>(data);
            if (asynccallbackinfo != nullptr) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetAllNotificationEnabledBundles(asynccallbackinfo->bundleOptionVector);
                ANS_LOGD("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiGetAllNotificationEnableStatus, (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        ANS_LOGD("Callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
