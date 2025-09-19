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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H

#include "common.h"
#include "ui_content.h"
#include "ability.h"
#include "ability_context.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;
using JsAnsCallbackComplete = void(napi_env, void*);
struct NotificationExtensionUserGrantedParams {
    NotificationBundleOption targetBundle;
    bool enabled = false;
    std::vector<sptr<NotificationBundleOption>> bundles;
};
struct AsyncCallbackInfoNotificationExtensionUserGranted {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    NotificationExtensionUserGrantedParams params;
};

struct OpenSettingsParams {
    std::shared_ptr<OHOS::AbilityRuntime::Context> context;
};

struct AsyncCallbackInfoOpenSettings {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    OpenSettingsParams params;
    CallbackPromiseInfo info;
};

bool CreateSettingsUiExtensionSub(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName);
bool InitSub(napi_env env, AsyncCallbackInfoOpenSettings* callbackInfo, JsAnsCallbackComplete complete);
void ProcessStatusChangedSub(int32_t code);
void CreateExtensionSub(AsyncCallbackInfoOpenSettings* asynccallbackinfo);
napi_value ParseOpenSettingsParameters(const napi_env &env, const napi_callback_info &info, OpenSettingsParams &params);
napi_value NapiNotificationExtensionOpenSubscriptionSettings(napi_env env, napi_callback_info info);
napi_value NapiGetAllSubscriptionBundles(napi_env env, napi_callback_info info);

class SettingsSubModalExtensionCallback {
    public:
        SettingsSubModalExtensionCallback();
        ~SettingsSubModalExtensionCallback();
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
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H