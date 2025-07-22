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

#include "ani_open_settings.h"

#include "ans_log_wrapper.h"
#include "ets_error_utils.h"
#include "notification_helper.h"
#include "ani_common_util.h"
#include "sts_throw_erro.h"
#include "ani_ans_dialog_callback.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;
static std::atomic<bool> isExist = false;
const int32_t ERR__INVALID_WANT = 1011;
bool GetOpenSettingsInfo(ani_env *env, ani_object content, std::shared_ptr<OpenSettingsInfo> &info)
{
    ANS_LOGD("enter");

    ani_status status = ANI_OK;
    ani_boolean stageMode = ANI_FALSE;
    status = OHOS::AbilityRuntime::IsStageContext(env, content, stageMode);
    ANS_LOGD("status %{public}d, stageMode %{public}d", status, stageMode);
    if (ANI_OK != status || stageMode != ANI_TRUE) {
        ANS_LOGE("Only support stage mode");
        std::string msg = "Incorrect parameter types.Only support stage mode.";
        ANS_LOGE("sts GetOpenSettingsInfo ERROR_PARAM_INVALID");
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    info->context = OHOS::AbilityRuntime::GetStageModeContext(env, content);
    return true;
}

bool CreateUiExtCallback(ani_env *env, std::shared_ptr<SettingsModalExtensionCallback>& uiExtCallback,
    Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks, std::shared_ptr<OpenSettingsInfo> &info,
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext, std::string &bundleName)
{
    if (!uiExtCallback->Init(env, info, StsAsyncCompleteCallbackOpenSettings)) {
        ANS_LOGE("error");
        info->errorCode = OHOS::Notification::ERROR_INTERNAL_ERROR;
        StsAsyncCompleteCallbackOpenSettings(env, info);
        return false;
    }
    uiExtCallback->SetAbilityContext(abilityContext);
    uiExtCallback->SetBundleName(bundleName);
    uiExtensionCallbacks = {
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
    return true;
}

bool CreateSettingsUIExtension(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName,
    ani_env *env, std::shared_ptr<OpenSettingsInfo> &info)
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
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks;
    if (!CreateUiExtCallback(env, uiExtCallback, uiExtensionCallbacks, info, abilityContext,
        bundleName)) {
        ANS_LOGE("CreateUiExtCallback fail");
        return false;
    }

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

void StsAsyncCompleteCallbackOpenSettings(ani_env *env, std::shared_ptr<OpenSettingsInfo> info)
{
    ANS_LOGD("enter");
    if (env == nullptr) {
        ANS_LOGD("env is null");
        return;
    }
    ani_status status;
    int32_t errorCode = ERR_OK;
    if (info->errorCode == OHOS::Notification::ERROR_SETTING_WINDOW_EXIST) {
        errorCode = OHOS::Notification::ERROR_SETTING_WINDOW_EXIST;
    } else if (info->errorCode == ERR__INVALID_WANT) {
        errorCode = ERR__INVALID_WANT;
    } else {
        errorCode = info->errorCode ==
            ERR_OK ? ERR_OK : NotificationSts::GetExternalCode(info->errorCode);
    }

    if (errorCode == ERR_OK) {
        ANS_LOGD("Resolve. errorCode %{public}d", errorCode);
        ani_object ret = OHOS::AppExecFwk::CreateInt(env, errorCode);
        if (ret == nullptr) {
            ANS_LOGD("createInt faild");
            NotificationSts::ThrowStsErroWithMsg(env, "");
            return;
        }
        if (ANI_OK != (status = env->PromiseResolver_Resolve(info->resolver, static_cast<ani_ref>(ret)))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
            NotificationSts::ThrowStsErroWithMsg(env, "");
        }
    } else {
        std::string errMsg = OHOS::NotificationSts::FindAnsErrMsg(errorCode);
        ANS_LOGD("reject. errorCode %{public}d errMsg %{public}s", errorCode, errMsg.c_str());
        ani_error rejection =
            static_cast<ani_error>(OHOS::NotificationSts::CreateError(env, errorCode, errMsg));
        if (ANI_OK != (status = env->PromiseResolver_Reject(info->resolver, rejection))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
            NotificationSts::ThrowStsErroWithMsg(env, "");
        }
    }
}

ani_object AniOpenNotificationSettings(ani_env *env, ani_object content)
{
    ANS_LOGD("sts AniOpenNotificationSettings call");
    std::shared_ptr<OpenSettingsInfo> info = std::make_shared<OpenSettingsInfo>();
    if (!GetOpenSettingsInfo(env, content, info)) {
        ANS_LOGE("sts AniOpenNotificationSettings GetOpenSettingsInfo fail");
        return nullptr;
    }
    if (info->context == nullptr) {
        ANS_LOGE("sts AniOpenNotificationSettings context is null");
        NotificationSts::ThrowStsErroWithMsg(env, "");
        return nullptr;
    }
    std::string bundleName {""};
    if (isExist.exchange(true)) {
        ANS_LOGE("sts AniOpenNotificationSettings ERROR_SETTING_WINDOW_EXIST");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_SETTING_WINDOW_EXIST,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_SETTING_WINDOW_EXIST));
        return nullptr;
    }
    ani_object aniPromise {};
    ani_resolver aniResolver {};
    if (ANI_OK != env->Promise_New(&aniResolver, &aniPromise)) {
        ANS_LOGD("Promise_New faild");
        return nullptr;
    }
    info->resolver = aniResolver;
    bool success = CreateSettingsUIExtension(info->context, bundleName, env, info);
    if (success) {
        info->errorCode = OHOS::Notification::ERR_ANS_DIALOG_POP_SUCCEEDED;
    } else {
        info->errorCode = OHOS::Notification::ERROR_INTERNAL_ERROR;
    }
    if (info->errorCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
        ANS_LOGE("error, code is %{public}d.", info->errorCode);
        StsAsyncCompleteCallbackOpenSettings(env, info);
        isExist.store(false);
        return nullptr;
    }
    ANS_LOGD("sts AniOpenNotificationSettings end");

    return aniPromise;
}

SettingsModalExtensionCallback::SettingsModalExtensionCallback()
{}

SettingsModalExtensionCallback::~SettingsModalExtensionCallback()
{}

bool SettingsModalExtensionCallback::Init(ani_env *env, std::shared_ptr<OpenSettingsInfo> info,
    StsSettingsModalExtensionCallbackComplete *complete)
{
    if (env == nullptr || info == nullptr || complete == nullptr) {
        ANS_LOGE("invalid data");
        return false;
    }
    ani_status status = ANI_OK;
    if ((status = env->GetVM(&vm_)) != ANI_OK) {
        ANS_LOGD("GetVM faild. status %{public}d", status);
        return false;
    }
    info_ = info;
    complete_ = complete;
    return true;
}

void SettingsModalExtensionCallback::ProcessStatusChanged(int32_t code, bool isAsync)
{
    ANS_LOGD("enter");
    if (vm_ == nullptr || info_ == nullptr || complete_ == nullptr) {
        ANS_LOGE("invalid data");
        AnsDialogHostClient::Destroy();
        return;
    }
    info_->errorCode = code;

    ani_env* env;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    if (isAsync) {
        aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    } else {
        aniResult = vm_->GetEnv(ANI_VERSION_1, &env);
    }
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    if (complete_) {
        complete_(env, info_);
    }
    if (isAsync && (aniResult = vm_->DetachCurrentThread()) != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}

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
    ProcessStatusChanged(code, false);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void SettingsModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ANS_LOGI("OnRemoteReady");
    ProcessStatusChanged(0, true);
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
}
}