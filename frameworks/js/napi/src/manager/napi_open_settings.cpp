/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "napi_open_settings.h"
#include <uv.h>
#include "napi_base_context.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int OPEN_NOTIFICATION_SETTINGS_MAX_PARA = 1;
static napi_env env_ = nullptr;
static AsyncCallbackInfoOpenSettings* callbackInfo_ = nullptr;
static JsAnsCallbackComplete* complete_ = nullptr;
static std::atomic<bool> isExist = false;

void NapiAsyncCompleteCallbackOpenSettings(napi_env env, void *data)
{
    ANS_LOGD("enter NapiAsyncCompleteCallbackOpenSettings");
    if (data == nullptr) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    auto* asynccallbackinfo = static_cast<AsyncCallbackInfoOpenSettings*>(data);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t errorCode = ERR_OK;
    if (asynccallbackinfo->info.errorCode == ERROR_SETTING_WINDOW_EXIST) {
        errorCode = ERROR_SETTING_WINDOW_EXIST;
    } else {
        errorCode = asynccallbackinfo->info.errorCode ==
            ERR_OK ? ERR_OK : Common::ErrorToExternal(asynccallbackinfo->info.errorCode);
    }
    if (asynccallbackinfo->info.isCallback) {
        Common::SetCallback(env, asynccallbackinfo->info.callback, errorCode, result, true);
    } else {
        Common::SetPromise(env, asynccallbackinfo->info.deferred, errorCode, result, true);
    }
    if (asynccallbackinfo->info.callback != nullptr) {
        napi_delete_reference(env, asynccallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
}

napi_value NapiOpenNotificationSettings(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiOpenNotificationSettings start");
    OpenSettingsParams params {};
    if (ParseOpenSettingsParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoOpenSettings *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoOpenSettings {
            .env = env, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "openNotificationSettings", NAPI_AUTO_LENGTH, &resourceName);

    auto createExtension = [](napi_env env, void* data) {
    };
    auto jsCb = [](napi_env env, napi_status status, void* data) {
        ANS_LOGD("enter");
        if (data == nullptr) {
            ANS_LOGE("data is invalid");
            return;
        }
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoOpenSettings*>(data);
        CreateExtension(asynccallbackinfo);
        ErrCode errCode = asynccallbackinfo->info.errorCode;
        if (errCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
            ANS_LOGE("error, code is %{public}d.", errCode);
            NapiAsyncCompleteCallbackOpenSettings(env, static_cast<void*>(asynccallbackinfo));
            isExist.store(false);
            return;
        }
        if (!Init(env, asynccallbackinfo, NapiAsyncCompleteCallbackOpenSettings)) {
            ANS_LOGE("error");
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
            NapiAsyncCompleteCallbackOpenSettings(env, static_cast<void*>(asynccallbackinfo));
            return;
        }
        ANS_LOGD("jsCb end");
    };

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        createExtension,
        jsCb,
        static_cast<void*>(asynccallbackinfo),
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    ANS_LOGD("NapiOpenNotificationSettings end");
    return promise;
}

napi_value ParseOpenSettingsParameters(const napi_env &env, const napi_callback_info &info, OpenSettingsParams &params)
{
    ANS_LOGD("enter");

    size_t argc = OPEN_NOTIFICATION_SETTINGS_MAX_PARA;
    napi_value argv[OPEN_NOTIFICATION_SETTINGS_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc == 0) {
        return Common::NapiGetNull(env);
    }

    // argv[0]: context
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
            params.context = context;
        } else {
            ANS_LOGE("Only support stage mode");
            std::string msg = "Incorrect parameter types.Only support stage mode.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
    }
    return Common::NapiGetNull(env);
}

bool CreateSettingsUIExtension(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName)
{
    if (context == nullptr) {
        ANS_LOGE("Get context failed");
        return false;
    }

    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        ANS_LOGE("abilityContext is null");
        return false;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("uiContent is null");
        return false;
    }

    AAFwk::Want want;
    std::string targetBundleName = "com.ohos.sceneboard";
    std::string targetAbilityName = "NotificationManangerUIExtensionAbility";
    want.SetElementName(targetBundleName, targetAbilityName);

    std::string typeKey = "ability.want.params.uiExtensionType";
    std::string typeValue = "sys/commonUI";
    want.SetParam(typeKey, typeValue);

    auto uiExtCallback = std::make_shared<SettingsModalExtensionCallback>();
    uiExtCallback->SetAbilityContext(abilityContext);
    uiExtCallback->SetBundleName(bundleName);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        .onRelease =
            std::bind(&SettingsModalExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        .onResult = std::bind(&SettingsModalExtensionCallback::OnResult, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2),
        .onReceive =
            std::bind(&SettingsModalExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        .onError = std::bind(&SettingsModalExtensionCallback::OnError, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .onRemoteReady =
            std::bind(&SettingsModalExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        .onDestroy = std::bind(&SettingsModalExtensionCallback::OnDestroy, uiExtCallback),
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;

    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ANS_LOGI("Create end, sessionId: %{public}d", sessionId);
    if (sessionId == 0) {
        ANS_LOGE("Create component failed, sessionId is 0");
        return false;
    }
    uiExtCallback->SetSessionId(sessionId);
    return true;
}

bool Init(napi_env env, AsyncCallbackInfoOpenSettings* callbackInfo,
    JsAnsCallbackComplete complete)
{
    ANS_LOGD("enter JsAnsCallback::Init");
    if (env == nullptr || callbackInfo == nullptr || complete == nullptr) {
        ANS_LOGE("invalid data");
        return false;
    }
    env_ = env;
    callbackInfo_ = callbackInfo;
    complete_ = complete;
    return true;
}

void ProcessStatusChanged(int32_t code)
{
    ANS_LOGD("enter");
    std::unique_ptr<AsyncCallbackInfoOpenSettings> callbackInfo(callbackInfo_);
    if (env_ == nullptr || callbackInfo == nullptr || complete_ == nullptr) {
        ANS_LOGE("invalid data");
        return;
    }

    callbackInfo->info.errorCode = code;

    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ANS_LOGE("loop is nullptr");
        return;
    }

    auto work = std::make_unique<uv_work_t>();
    struct WorkData {
        decltype(env_) env = nullptr;
        decltype(callbackInfo_) callbackInfo = nullptr;
        decltype(complete_) complete = nullptr;
    };
    auto workData = std::make_unique<WorkData>();
    workData->env = env_;
    workData->callbackInfo = callbackInfo_;
    workData->complete = complete_;

    work->data = static_cast<void*>(workData.get());
    auto jsCb = [](uv_work_t* work, int status) {
        ANS_LOGD("enter ProcessStatusChanged jsCb");
        std::unique_ptr<uv_work_t> workSP(work);
        if (work == nullptr || work->data == nullptr) {
            ANS_LOGE("invalid data");
            return;
        }
        auto* data = static_cast<WorkData*>(work->data);
        std::unique_ptr<WorkData> dataSP(data);
        std::unique_ptr<AsyncCallbackInfoOpenSettings> callbackInfoSP(data->callbackInfo);
        if (data->env == nullptr ||
            data->callbackInfo == nullptr ||
            data->complete == nullptr) {
            return;
        }
        auto* callbackInfoPtr = callbackInfoSP.release();
        data->complete(data->env, static_cast<void*>(callbackInfoPtr));
    };

    int ret = uv_queue_work_with_qos(loop,
        work.get(),
        [](uv_work_t *work) {},
        jsCb,
        uv_qos_user_initiated);
    if (ret != 0) {
        ANS_LOGE("uv_queue_work failed");
        return;
    }
    callbackInfo.release();
    workData.release();
    work.release();
}

void CreateExtension(AsyncCallbackInfoOpenSettings* asynccallbackinfo)
{
    if (asynccallbackinfo->params.context != nullptr) {
        ANS_LOGD("stage mode");
        std::string bundleName {""};
        if (isExist.exchange(true)) {
            ANS_LOGE("SettingsUIExtension existed");
            asynccallbackinfo->info.errorCode = ERROR_SETTING_WINDOW_EXIST;
            return;
        }
        bool success = CreateSettingsUIExtension(asynccallbackinfo->params.context, bundleName);
        if (success) {
            asynccallbackinfo->info.errorCode = ERR_ANS_DIALOG_POP_SUCCEEDED;
        } else {
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        }
    } else {
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("done, code is %{public}d.", asynccallbackinfo->info.errorCode);
}

SettingsModalExtensionCallback::SettingsModalExtensionCallback()
{}

SettingsModalExtensionCallback::~SettingsModalExtensionCallback()
{}


/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void SettingsModalExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    ANS_LOGD("OnResult");
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void SettingsModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    ANS_LOGD("OnReceive");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void SettingsModalExtensionCallback::OnRelease(int32_t releaseCode)
{
    ANS_LOGD("OnRelease");
    ReleaseOrErrorHandle(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void SettingsModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ANS_LOGE("OnError, code = %{public}d,name = %{public}s, message = %{public}s", code, name.c_str(), message.c_str());
    ReleaseOrErrorHandle(code);
    ProcessStatusChanged(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void SettingsModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ANS_LOGI("OnRemoteReady");
    ProcessStatusChanged(0);
}

/*
 * when UIExtensionComponent destructed
 */
void SettingsModalExtensionCallback::OnDestroy()
{
    ANS_LOGI("OnDestroy");
    isExist.store(false);
}


void SettingsModalExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void SettingsModalExtensionCallback::SetBundleName(std::string bundleName)
{
    this->bundleName_ = bundleName;
}

void SettingsModalExtensionCallback::SetAbilityContext(
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext)
{
    this->abilityContext_ = abilityContext;
}

void SettingsModalExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    ANS_LOGD("ReleaseOrErrorHandle start");
    Ace::UIContent* uiContent = this->abilityContext_->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("uiContent is null");
        return;
    }
    uiContent->CloseModalUIExtension(this->sessionId_);
    ANS_LOGD("ReleaseOrErrorHandle end");
    return;
}

}  // namespace NotificationNapi
}  // namespace OHOS