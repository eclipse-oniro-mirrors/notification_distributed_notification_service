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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBER_EXTENSION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBER_EXTENSION_H
#include <memory>

#include "common_event_data.h"
#include "js_runtime.h"
#include "native_engine/native_reference.h"
#include "native_engine/native_value.h"
#include "runtime.h"
#include "notification_subscriber_extension.h"

namespace OHOS {
namespace NotificationNapi {
using namespace Notification;
class JsNotificationSubscriberExtension : public NotificationSubscriberExtension {
public:
    explicit JsNotificationSubscriberExtension(AbilityRuntime::JsRuntime& jsRuntime);
    virtual ~JsNotificationSubscriberExtension() override;

    /**
        * @brief Create JsNotificationSubscriberExtension.
        *
        * @param runtime The runtime.
        * @return The JsNotificationSubscriberExtension instance.
        */
    static JsNotificationSubscriberExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
                const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
                std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
                const sptr<IRemoteObject>& token) override;

    void OnStart(const AAFwk::Want& want) override;

    sptr<IRemoteObject> OnConnect(const AAFwk::Want& want) override;

    void OnDisconnect(const AAFwk::Want& want) override;

    void OnStop() override;

    virtual void OnDestroy() override;
    virtual NotificationSubscriberExtensionResult OnReceiveMessage(
        const std::shared_ptr<NotificationInfo> info) override;
    virtual NotificationSubscriberExtensionResult OnCancelMessages(
        const std::shared_ptr<std::vector<std::string>> hashCodes) override;

    void ExecNapiWrap(napi_env env, napi_value obj);

    std::weak_ptr<JsNotificationSubscriberExtension> GetWeakPtr();

private:
    napi_value CreateOnCancelMessagesResult(napi_env env, const std::shared_ptr<std::vector<std::string>> hashCodes);

private:
    AbilityRuntime::JsRuntime& jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;
};
} // namespace NotificationNapi
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBER_EXTENSION_H
