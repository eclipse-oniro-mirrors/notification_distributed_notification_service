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

#include "ani_ans_dialog_callback.h"

#include "ans_log_wrapper.h"
#include "inner_errors.h"
#include "notification_helper.h"

namespace OHOS {
namespace NotificationManagerSts {

bool StsAnsDialogCallback::Init(
    ani_env *env, std::shared_ptr<EnableNotificationInfo> info, StsAnsDialogCallbackComplete *complete)
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

void StsAnsDialogCallback::ProcessDialogStatusChanged(const DialogStatusData &data)
{
    ANS_LOGD("enter");
    if (vm_ == nullptr || info_ == nullptr || complete_ == nullptr) {
        ANS_LOGE("invalid data");
        AnsDialogHostClient::Destroy();
        return;
    }
    info_->errorCode = StsAnsDialogCallback::GetErrCodeFromStatus(
        static_cast<EnabledDialogStatus>(data.GetStatus()));

    ani_env* env;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        AnsDialogHostClient::Destroy();
        return;
    }
    if (complete_) {
        complete_(env, info_);
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        AnsDialogHostClient::Destroy();
        return;
    }
    AnsDialogHostClient::Destroy();
}

int32_t StsAnsDialogCallback::GetErrCodeFromStatus(EnabledDialogStatus status)
{
    switch (static_cast<EnabledDialogStatus>(status)) {
        case EnabledDialogStatus::ALLOW_CLICKED:
            return ERR_OK;
        case EnabledDialogStatus::DENY_CLICKED:
            return CJSystemapi::Notification::ERR_ANS_NOT_ALLOWED;
        case EnabledDialogStatus::CRASHED:
            return CJSystemapi::Notification::ERROR_INTERNAL_ERROR;
        default:
            return CJSystemapi::Notification::ERROR_INTERNAL_ERROR;
    }
    return CJSystemapi::Notification::ERROR_INTERNAL_ERROR;
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
    ANS_LOGD("OnResult");
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void ModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    ANS_LOGD("OnReceive");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void ModalExtensionCallback::OnRelease(int32_t releaseCode)
{
    ANS_LOGD("OnRelease");
    ReleaseOrErrorHandle(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void ModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ANS_LOGE("OnError, name = %{public}s, message = %{public}s", name.c_str(), message.c_str());
    ReleaseOrErrorHandle(code);
    NotificationHelper::RemoveEnableNotificationDialog();
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void ModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ANS_LOGD("OnRemoteReady");
}

/*
 * when UIExtensionComponent destructed
 */
void ModalExtensionCallback::OnDestroy()
{
    ANS_LOGD("OnDestroy");
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