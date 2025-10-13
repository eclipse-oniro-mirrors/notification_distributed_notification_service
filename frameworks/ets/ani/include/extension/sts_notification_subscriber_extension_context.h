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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_CONTEXT_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_CONTEXT_INFO_H

#include "ani.h"
#include "context.h"
#include "ohos_application.h"
#include "notification_subscriber_extension_context.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AbilityRuntime;
using NotificationSubscriberExtensionContext = OHOS::Notification::NotificationSubscriberExtensionContext;

ani_object CreateNotificationSubscriberExtensionContext(ani_env *env,
    std::shared_ptr<NotificationSubscriberExtensionContext> context,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application);
}
}
#endif //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_ANI_STS_SUBSCRIBER_EXTENSION_CONTEXT_INFO_H