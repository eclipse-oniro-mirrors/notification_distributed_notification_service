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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_INFO_H

#include "ability_handler.h"
#include "ani.h"
#include "context.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "notification_subscriber_extension.h"
#include "notification_subscriber_extension_context.h"
#include "ohos_application.h"
#include "sts_notification_subscriber_extension_context.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::Notification;
using NotificationSubscriberExtension = OHOS::Notification::NotificationSubscriberExtension;
using NotificationInfo = OHOS::Notification::NotificationInfo;

class StsNotificationSubscriberExtension : public NotificationSubscriberExtension {
public:
    explicit StsNotificationSubscriberExtension(AbilityRuntime::ETSRuntime &stsRuntime);
    virtual ~StsNotificationSubscriberExtension() override;

    static StsNotificationSubscriberExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& stsRuntime);

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

    void ResetEnv(ani_env* env);

    std::weak_ptr<StsNotificationSubscriberExtension> GetWeakPtr();
    
    NotificationSubscriberExtensionResult CallObjectMethod(const char* name, const char* signature, ...);

private:
    void BindContext(ani_env *env, const std::shared_ptr<OHOSApplication> &application);
    ani_object CreateSTSContext(ani_env *env, std::shared_ptr<NotificationSubscriberExtensionContext> context,
        const std::shared_ptr<OHOSApplication> &application);
    AbilityRuntime::ETSRuntime& stsRuntime_;
    std::unique_ptr<AppExecFwk::ETSNativeReference> stsObj_;
};
}
}
#endif //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_INFO_H