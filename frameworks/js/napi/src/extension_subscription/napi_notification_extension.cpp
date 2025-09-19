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
#include <uv.h>
#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_base_context.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
const int OPEN_NOTIFICATION_SETTINGS_MAX_PARA = 1;
static napi_env subenv_ = nullptr;
static AsyncCallbackInfoOpenSettings* subcallbackInfo_ = nullptr;
static JsAnsCallbackComplete* subcomplete_ = nullptr;
static std::atomic<bool> subisExist = false;
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
    if (!asynccallbackinfo) {
        return;
    }
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
}

void NapiAsyncCompleteCallbackOpenSettings(napi_env env, void *data)
{
    ANS_LOGD("called");
    if (data == nullptr) {
        ANS_LOGE("null data");
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
            ERR_OK ? ERR_OK : OHOS::Notification::ErrorToExternal(asynccallbackinfo->info.errorCode);
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

bool CreateSettingsUiExtensionSub(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName)
{
    if (context == nullptr) {
        ANS_LOGE("null context");
        return false;
    }

    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        ANS_LOGE("null abilityContex");
        return false;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("null uiContent");
        return false;
    }

    AAFwk::Want want;
    std::string targetBundleName = "com.ohos.sceneboard";
    std::string targetAbilityName = "NotificationManangerUIExtensionAbility";
    want.SetElementName(targetBundleName, targetAbilityName);

    std::string typeKey = "ability.want.params.uiExtensionType";
    std::string typeValue = "sys/commonUI";
    want.SetParam(typeKey, typeValue);

    auto uiExtCallback = std::make_shared<SettingsSubModalExtensionCallback>();
    uiExtCallback->SetAbilityContext(abilityContext);
    uiExtCallback->SetBundleName(bundleName);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        .onRelease = std::bind(&SettingsSubModalExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        .onResult = std::bind(&SettingsSubModalExtensionCallback::OnResult, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2),
        .onReceive =
            std::bind(&SettingsSubModalExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        .onError = std::bind(&SettingsSubModalExtensionCallback::OnError, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .onRemoteReady = std::bind(&SettingsSubModalExtensionCallback::OnRemoteReady, uiExtCallback,
            std::placeholders::_1),
        .onDestroy = std::bind(&SettingsSubModalExtensionCallback::OnDestroy, uiExtCallback),
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    config.isWindowModeFollowHost = true;

    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ANS_LOGI("Create end, sessionId: %{public}d", sessionId);
    if (sessionId == 0) {
        ANS_LOGE("Create component failed, sessionId is 0");
        return false;
    }
    uiExtCallback->SetSessionId(sessionId);
    return true;
}

bool InitSub(napi_env env, AsyncCallbackInfoOpenSettings* callbackInfo,
    JsAnsCallbackComplete complete)
{
    ANS_LOGD("called");
    if (env == nullptr || callbackInfo == nullptr || complete == nullptr) {
        ANS_LOGE("invalid data");
        return false;
    }
    subenv_ = env;
    subcallbackInfo_ = callbackInfo;
    subcomplete_ = complete;
    return true;
}

void ProcessStatusChangedSub(int32_t code)
{
    ANS_LOGD("called");
    std::unique_ptr<AsyncCallbackInfoOpenSettings> callbackInfo(subcallbackInfo_);
    if (subenv_ == nullptr || callbackInfo == nullptr || subcomplete_ == nullptr) {
        ANS_LOGE("invalid data");
        return;
    }

    callbackInfo->info.errorCode = code;

    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(subenv_, &loop);
    if (loop == nullptr) {
        ANS_LOGE("null loop");
        return;
    }

    auto work = std::make_unique<uv_work_t>();
    struct WorkData {
        decltype(subenv_) env = nullptr;
        decltype(subcallbackInfo_) callbackInfo = nullptr;
        decltype(subcomplete_) complete = nullptr;
    };
    auto workData = std::make_unique<WorkData>();
    workData->env = subenv_;
    workData->callbackInfo = subcallbackInfo_;
    workData->complete = subcomplete_;

    work->data = static_cast<void*>(workData.get());
    auto jsCb = [](uv_work_t* work, int status) {
        std::unique_ptr<uv_work_t> workSP(work);
        if (work == nullptr || work->data == nullptr) {
            ANS_LOGE("invalid data");
            return;
        }
        auto* data = static_cast<WorkData*>(work->data);
        std::unique_ptr<WorkData> dataSP(data);
        std::unique_ptr<AsyncCallbackInfoOpenSettings> callbackInfoSP(data->callbackInfo);
        if (data->env == nullptr || data->callbackInfo == nullptr || data->complete == nullptr) {
            return;
        }
        auto* callbackInfoPtr = callbackInfoSP.release();
        data->complete(data->env, static_cast<void*>(callbackInfoPtr));
    };

    int ret = uv_queue_work_with_qos(loop, work.get(), [](uv_work_t *work) {}, jsCb, uv_qos_user_initiated);
    if (ret != 0) {
        ANS_LOGE("uv_queue_work failed");
        return;
    }
    callbackInfo.release();
    workData.release();
    work.release();
}

void CreateExtensionSub(AsyncCallbackInfoOpenSettings* asynccallbackinfo)
{
    if (asynccallbackinfo->params.context != nullptr) {
        ANS_LOGD("stage mode");
        std::string bundleName {""};
        if (subisExist.exchange(true)) {
            ANS_LOGE("SettingsUIExtension existed");
            asynccallbackinfo->info.errorCode = ERROR_SETTING_WINDOW_EXIST;
            return;
        }
        bool success = CreateSettingsUiExtensionSub(asynccallbackinfo->params.context, bundleName);
        if (success) {
            asynccallbackinfo->info.errorCode = ERR_ANS_DIALOG_POP_SUCCEEDED;
        } else {
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        }
    } else {
        ANS_LOGD("un stage mode");
    }
    ANS_LOGI("errorCode: %{public}d", asynccallbackinfo->info.errorCode);
}


napi_value ParseOpenSettingsParameters(const napi_env &env, const napi_callback_info &info, OpenSettingsParams &params)
{
    ANS_LOGD("called");

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

napi_value QueueAsyncWork(napi_env env, AsyncCallbackInfoOpenSettings* p)
{
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, p->info, promise);

    napi_value resourceName  = nullptr;
    napi_create_string_latin1(env, "openSubscribeSettings", NAPI_AUTO_LENGTH, &resourceName);

    auto ce = [](napi_env, void*) {};
    auto cb = [](napi_env env, napi_status, void* data) {
        auto* asynccallbackinfo = static_cast<AsyncCallbackInfoOpenSettings*>(data);
        CreateExtensionSub(asynccallbackinfo);
        ErrCode errCode = asynccallbackinfo->info.errorCode;
        if (errCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
            ANS_LOGE("errCode: %{public}d.", errCode);
            NapiAsyncCompleteCallbackOpenSettings(env, static_cast<void*>(asynccallbackinfo));
            if (errCode != ERROR_SETTING_WINDOW_EXIST) subisExist.store(false);
            return;
        }
        if (!InitSub(env, asynccallbackinfo, NapiAsyncCompleteCallbackOpenSettings)) {
            ANS_LOGE("init error");
            asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
            NapiAsyncCompleteCallbackOpenSettings(env, static_cast<void*>(asynccallbackinfo));
            return;
        }
        ANS_LOGD("subscribe jsCb end");
    };

    napi_create_async_work(env, nullptr, resourceName, ce, cb, static_cast<void*>(p), &p->asyncWork);
    napi_queue_async_work_with_qos(env, p->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value NapiNotificationExtensionOpenSubscriptionSettings(napi_env env, napi_callback_info info)
{
    ANS_LOGD("start subscribe settings");
    ErrCode permRet = NotificationHelper::CanOpenSubscribeSettings();
    if (permRet != ERR_OK) {
        ANS_LOGE("OpenSettings call failed, err=%{public}d", permRet);
        Common::NapiThrow(env, ERR_ANS_PERMISSION_DENIED);
        return Common::NapiGetUndefined(env);
    }

    OpenSettingsParams params {};
    if (ParseOpenSettingsParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto* asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoOpenSettings {
        .env = env, .params = params
    };
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, nullptr);
    }

    ANS_LOGD("end subscribe settings");
    return QueueAsyncWork(env, asynccallbackinfo);
}

napi_value NapiGetAllSubscriptionBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    AsyncCallbackInfoNotificationExtensionUserGranted* asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoNotificationExtensionUserGranted { .env = env, .asyncWork = nullptr };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllSubscriptionBundles", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("getAllSubscriptionBundles work excute.");
            AsyncCallbackInfoNotificationExtensionUserGranted *asynccallbackinfo =
                static_cast<AsyncCallbackInfoNotificationExtensionUserGranted *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetAllSubscriptionBundles(asynccallbackinfo->params.bundles);
                ANS_LOGI("errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackRetrunBundleOptionArray,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

SettingsSubModalExtensionCallback::SettingsSubModalExtensionCallback()
{}

SettingsSubModalExtensionCallback::~SettingsSubModalExtensionCallback()
{}

void SettingsSubModalExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    ANS_LOGD("called");
}

void SettingsSubModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    ANS_LOGD("called");
}

void SettingsSubModalExtensionCallback::OnRelease(int32_t releaseCode)
{
    ANS_LOGD("OnRelease");
    ReleaseOrErrorHandle(releaseCode);
}

void SettingsSubModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ANS_LOGD("called, code = %{public}d,name = %{public}s, message = %{public}s", code, name.c_str(), message.c_str());
    ReleaseOrErrorHandle(code);
    ProcessStatusChangedSub(code);
}

void SettingsSubModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ANS_LOGD("called");
    ProcessStatusChangedSub(0);
}

void SettingsSubModalExtensionCallback::OnDestroy()
{
    ANS_LOGD("called");
    subisExist.store(false);
}


void SettingsSubModalExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void SettingsSubModalExtensionCallback::SetBundleName(std::string bundleName)
{
    this->bundleName_ = bundleName;
}

void SettingsSubModalExtensionCallback::SetAbilityContext(
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext)
{
    this->abilityContext_ = abilityContext;
}

void SettingsSubModalExtensionCallback::ReleaseOrErrorHandle(int32_t code)
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
