/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cj_modal_extension_callback.h"

#include <future>

#include "ans_dialog_host_client.h"
#include "ans_notification.h"
#include "ans_service_errors.h"
#include "ability_context.h"
#include "notification_manager_impl.h"
#include "notification_manager_log.h"
#include "singleton.h"
namespace OHOS {
namespace CJSystemapi {
namespace Notification {

CjModalExtensionCallback::CjModalExtensionCallback()
{}

CjModalExtensionCallback::~CjModalExtensionCallback()
{}

void CjModalExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    LOGD("called");
}

void CjModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGD("called");
}

void CjModalExtensionCallback::OnRelease(int32_t releaseCode)
{
    LOGD("called");
    ReleaseOrErrorHandle(releaseCode);
}

void CjModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& msg)
{
    LOGD("called, name = %{public}s, message = %{public}s", name.c_str(), msg.c_str());
    ReleaseOrErrorHandle(code);
    OHOS::Notification::AnsNotification::GetInstance()->RemoveEnableNotificationDialog();
}

void CjModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGD("called");
}

void CjModalExtensionCallback::OnDestroy()
{
    LOGD("called");
}

void CjModalExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void CjModalExtensionCallback::SetBundleName(const std::string& name)
{
    this->bundleName_ = name;
}

void CjModalExtensionCallback::SetAbilityContext(std::shared_ptr<AbilityRuntime::AbilityContext> ctx)
{
    this->abilityContext_ = ctx;
}

void CjModalExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    LOGD("start");
    if (this->abilityContext_ == nullptr) {
        LOGE("null abilityContext");
        return;
    }
    Ace::UIContent* uiContent = this->abilityContext_->GetUIContent();
    if (uiContent == nullptr) {
        LOGE("null uiContent");
        return;
    }
    uiContent->CloseModalUIExtension(this->sessionId_);
    LOGD("end");
    return;
}


} // namespace Notification
} // namespace CJSystemapi
} // namespace OHOS
