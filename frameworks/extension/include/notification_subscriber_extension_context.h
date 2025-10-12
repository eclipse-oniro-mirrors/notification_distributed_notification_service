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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_CONTEXT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_CONTEXT_H

#include "extension_context.h"
#include "want.h"

namespace OHOS {
namespace Notification {
class NotificationSubscriberExtensionContext : public AbilityRuntime::ExtensionContext {
public:
    NotificationSubscriberExtensionContext();

    virtual ~NotificationSubscriberExtensionContext();

    using SelfType = NotificationSubscriberExtensionContext;
    static const size_t CONTEXT_TYPE_ID;

protected:
    bool IsContext(size_t contextTypeId) override
    {
        return contextTypeId == CONTEXT_TYPE_ID || ExtensionContext::IsContext(contextTypeId);
    }

    bool CheckCallerIsSystemApp();
    bool VerifyCallingPermission(const std::string& permissionName) const;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_CONTEXT_H