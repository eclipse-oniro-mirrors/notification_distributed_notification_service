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
#include "common_event_manager.h"

namespace OHOS {
namespace NotificationNapi {
const int IS_NOTIFICATION_ENABLE_MAX_PARA = 2;
void AsyncCompleteCallbackNapiEnableNotification(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
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
    ANS_LOGD("called");
    EnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
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
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiEnableNotification,
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

void AsyncCompleteCallbackNapiIsNotificationEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
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
    ANS_LOGD("called");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
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
                    ANS_LOGI("userId:%{public}d", asynccallbackinfo->params.userId);
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.userId, asynccallbackinfo->allowed);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotifySelf(
                        asynccallbackinfo->allowed);
                }
                ANS_LOGI("errorCode:%{public}d, allowed:%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackNapiIsNotificationEnabled,
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

napi_value NapiIsNotificationEnabledSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
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
                ANS_LOGD("errorCode: %{public}d, allowed:%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackNapiIsNotificationEnabled,
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

void NapiAsyncCompleteCallbackRequestEnableNotification(napi_env env, void *data)
{
    ANS_LOGD("called");
    if (data == nullptr) {
        ANS_LOGE("null data");
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
    ANS_LOGD("called");
    IsEnableParams params {};
    if (ParseRequestEnableParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnable {
            .env = env, .params = params, .newInterface = true};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "RequestEnableNotification", NAPI_AUTO_LENGTH, &resourceName);

    auto ipcCall = [](napi_env env, void* data) {
        ANS_LOGD("called");
        if (data == nullptr) {
            ANS_LOGE("null data");
            return;
        }
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
        sptr<AnsDialogHostClient> client = nullptr;
        AnsDialogHostClient::CreateIfNullptr(client);
        if (client == nullptr) {
            ANS_LOGE("create client fail");
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
            return;
        }

        if (asynccallbackinfo->params.context != nullptr) {
            ANS_LOGD("stage mode");
            bool canPop = false;
            std::string bundleName {""};
            ErrCode errCode = NotificationHelper::CanPopEnableNotificationDialog(client, canPop, bundleName);
            ANS_LOGI("errCode:%{public}d, canPop:%{public}d", errCode, canPop);
            if (canPop == false) {
                asynccallbackinfo->info.errorCode = errCode;
                return;
            }
            asynccallbackinfo->bundleName = bundleName;
        } else {
            ANS_LOGD("un stage mode");
            std::string deviceId {""};
            asynccallbackinfo->info.errorCode =
            NotificationHelper::RequestEnableNotification(deviceId, client,
                asynccallbackinfo->params.callerToken);
        }
        ANS_LOGI("errorCode: %{public}d", asynccallbackinfo->info.errorCode);
    };
    auto jsCb = [](napi_env env, napi_status status, void* data) {
        ANS_LOGD("called");
        if (data == nullptr) {
            ANS_LOGE("null data");
            return;
        }
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable*>(data);
        if (!asynccallbackinfo->bundleName.empty()) {
            bool success = CreateUIExtension(asynccallbackinfo->params.context, asynccallbackinfo->bundleName);
            if (success) {
                asynccallbackinfo->info.errorCode = ERR_ANS_DIALOG_POP_SUCCEEDED;
            } else {
                asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
                NotificationHelper::RemoveEnableNotificationDialog();
            }
        }
        ErrCode errCode = asynccallbackinfo->info.errorCode;
        if (errCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
            ANS_LOGE("errCode: %{public}d", errCode);
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
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseRequestEnableParameters(const napi_env &env, const napi_callback_info &info, IsEnableParams &params)
{
    ANS_LOGD("called");

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
            SetEnableParam(params, env, argv[PARAM0]);
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
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    napi_value result = nullptr;
    AsyncCallbackInfoEnableStatus *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableStatus *>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
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
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    AsyncCallbackInfoEnableStatus *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnableStatus{ .env = env, .asyncWork = nullptr };
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
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
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiIsNotificationEnabledSync(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGD("null ParseParameters");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    bool allowed = false;
    NotificationHelper::IsAllowedNotifySelf(allowed);
    napi_value result = nullptr;
    napi_get_boolean(env, allowed, &result);
    return result;
}

bool CreateUIExtension(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName)
{
    if (context == nullptr) {
        ANS_LOGE("null context");
        return false;
    }

    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        ANS_LOGE("null abilityContext");
        return false;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("null uiContent");
        return false;
    }

    AAFwk::Want want;
    std::string targetBundleName = "com.ohos.notificationdialog";
    std::string targetAbilityName = "EnableNotificationDialog";
    want.SetElementName(targetBundleName, targetAbilityName);

    std::string typeKey = "ability.want.params.uiExtensionType";
    std::string typeValue = "sysDialog/common";
    want.SetParam(typeKey, typeValue);

    auto uiExtCallback = std::make_shared<ModalExtensionCallback>();
    uiExtCallback->SetAbilityContext(abilityContext);
    uiExtCallback->SetBundleName(bundleName);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        .onRelease = std::bind(&ModalExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        .onResult = std::bind(&ModalExtensionCallback::OnResult, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2),
        .onReceive = std::bind(&ModalExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        .onError = std::bind(&ModalExtensionCallback::OnError, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .onRemoteReady = std::bind(&ModalExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        .onDestroy = std::bind(&ModalExtensionCallback::OnDestroy, uiExtCallback),
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;

    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ANS_LOGI("sessionId: %{public}d", sessionId);
    if (sessionId == 0) {
        ANS_LOGE("Create component failed, sessionId is 0");
        return false;
    }
    uiExtCallback->SetSessionId(sessionId);
    return true;
}

void SetEnableParam(IsEnableParams &params, const napi_env &env, napi_value &object)
{
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, object);
    sptr<IRemoteObject> callerToken = nullptr;
    if (context != nullptr) {
        callerToken = context->GetToken();
    }
    params.context = context;
    params.callerToken = callerToken;
    params.hasCallerToken = true;
}

ModalExtensionCallback::ModalExtensionCallback()
{}

ModalExtensionCallback::~ModalExtensionCallback()
{}


/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void ModalExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    ANS_LOGD("called");
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void ModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    ANS_LOGD("called");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void ModalExtensionCallback::OnRelease(int32_t releaseCode)
{
    ANS_LOGI("called");
    ReleaseOrErrorHandle(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void ModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ANS_LOGD("called, name = %{public}s, message = %{public}s", name.c_str(), message.c_str());
    ReleaseOrErrorHandle(code);
    NotificationHelper::RemoveEnableNotificationDialog();
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void ModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ANS_LOGD("called");
}

/*
 * when UIExtensionComponent destructed
 */
void ModalExtensionCallback::OnDestroy()
{
    ANS_LOGD("called");
}


void ModalExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void ModalExtensionCallback::SetBundleName(std::string bundleName)
{
    this->bundleName_ = bundleName;
}

void ModalExtensionCallback::SetAbilityContext(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext)
{
    this->abilityContext_ = abilityContext;
}

void ModalExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    ANS_LOGD("start");
    Ace::UIContent* uiContent = this->abilityContext_->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("null uiContent");
        return;
    }
    uiContent->CloseModalUIExtension(this->sessionId_);
    ANS_LOGD("end");
    return;
}

}  // namespace NotificationNapi
}  // namespace OHOS
