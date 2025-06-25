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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_OPEN_SETTINGS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_OPEN_SETTINGS_H

#include "ani.h"
#include "ani_base_context.h"
#include "ans_dialog_host_client.h"
#include "ability.h"
#include "ability_context.h"
#include "ui_content.h"

namespace OHOS {
namespace NotificationManagerSts {
class SettingsModalExtensionCallback;
struct OpenSettingsInfo {
    int32_t errorCode = ANI_OK;
    std::shared_ptr<OHOS::AbilityRuntime::Context> context = nullptr;
    ani_resolver resolver {};
};

ani_object AniOpenNotificationSettings(ani_env *env, ani_object content);
bool GetOpenSettingsInfo(ani_env *env, ani_object content, std::shared_ptr<OpenSettingsInfo> &info);
bool CreateSettingsUIExtension(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName,
    ani_env *env, std::shared_ptr<OpenSettingsInfo> &info);
void StsAsyncCompleteCallbackOpenSettings(ani_env *env, std::shared_ptr<OpenSettingsInfo> info);

using StsSettingsModalExtensionCallbackComplete = void(ani_env *env, std::shared_ptr<OpenSettingsInfo> info);
void ProcessStatusChanged(int32_t code);
bool CreateUiExtCallback(ani_env *env, std::shared_ptr<SettingsModalExtensionCallback>& uiExtCallback,
    Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks, std::shared_ptr<OpenSettingsInfo> &info,
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext, std::string &bundleName);
class SettingsModalExtensionCallback {
public:
    SettingsModalExtensionCallback();
    ~SettingsModalExtensionCallback();
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
    bool Init(ani_env *env, std::shared_ptr<OpenSettingsInfo> info,
            StsSettingsModalExtensionCallbackComplete *complete);
    void ProcessStatusChanged(int32_t code, bool isAsync);
private:
    int32_t sessionId_ = 0;
    std::string bundleName_;
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext_;
    ani_vm *vm_ = nullptr;
    std::shared_ptr<OpenSettingsInfo> info_ = nullptr;
    StsSettingsModalExtensionCallbackComplete *complete_ = nullptr;
};
} // namespace NotificationManagerSts
} // namespace OHOS
#endif