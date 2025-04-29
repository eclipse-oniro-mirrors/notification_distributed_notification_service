/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_ENABLE_NOTIFICATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_ENABLE_NOTIFICATION_H

#include "common.h"
#include "enable_notification.h"
#include "ui_content.h"
#include "ability.h"
#include "ability_context.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

napi_value NapiEnableNotification(napi_env env, napi_callback_info info);
napi_value NapiIsNotificationEnabled(napi_env env, napi_callback_info info);
napi_value NapiIsNotificationEnabledSelf(napi_env env, napi_callback_info info);
napi_value NapiRequestEnableNotification(napi_env env, napi_callback_info info);
napi_value NapiGetAllNotificationEnabledBundles(napi_env env, napi_callback_info info);
napi_value ParseRequestEnableParameters(const napi_env &env, const napi_callback_info &info, IsEnableParams &params);
napi_value NapiIsNotificationEnabledSync(napi_env env, napi_callback_info info);
bool CreateUIExtension(std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::string &bundleName);
void SetEnableParam(IsEnableParams &params, const napi_env &env, napi_value &object);

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
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_ENABLE_NOTIFICATION_H