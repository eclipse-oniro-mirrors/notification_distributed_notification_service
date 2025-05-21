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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_ANS_DIALOG_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_ANS_DIALOG_CALLBACK_H
#include <string>
#include "ani.h"
#include "ani_base_context.h"
#include "ans_dialog_host_client.h"
#include "ability.h"
#include "ability_context.h"
#include "ui_content.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace Notification;

struct EnableNotificationInfo {
    int32_t errorCode = ANI_OK;
    std::string bundleName {""};
    bool stageMode = false;
    ani_resolver resolver {};
    std::shared_ptr<OHOS::AbilityRuntime::Context> context = nullptr;
    sptr<IRemoteObject> callerToken = nullptr;
};

using StsAnsDialogCallbackComplete = void(ani_env *env, std::shared_ptr<EnableNotificationInfo> info);
class StsAnsDialogCallback final : public AnsDialogCallbackNativeInterface {
public:
    StsAnsDialogCallback() = default;
    ~StsAnsDialogCallback() override = default;
    DISALLOW_COPY_AND_MOVE(StsAnsDialogCallback);

    bool Init(ani_env *env,
        std::shared_ptr<EnableNotificationInfo> info,
        StsAnsDialogCallbackComplete *complete);
    void ProcessDialogStatusChanged(const DialogStatusData& data) override;

private:
    ani_vm *vm_ = nullptr;
    std::shared_ptr<EnableNotificationInfo> info_ = nullptr;
    StsAnsDialogCallbackComplete *complete_ = nullptr;
    static int32_t GetErrCodeFromStatus(EnabledDialogStatus status);
};

class ModalExtensionCallback {
public:
    ModalExtensionCallback();
    ~ModalExtensionCallback();
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void SetSessionId(int32_t sessionId);
    void SetBundleName(std::string bundleName);
    void SetAbilityContext(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext);
    void ReleaseOrErrorHandle(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::string bundleName_;
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext_;
};

}
}

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_ANS_DIALOG_CALLBACK_H