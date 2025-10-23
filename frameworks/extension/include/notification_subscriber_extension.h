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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_H

#include "common_event_data.h"
#include "extension_base.h"
#include "runtime.h"
#include "notification_info.h"
#include "notification_subscriber_extension_context.h"

namespace OHOS {
namespace Notification {
enum class NotificationSubscriberExtensionResult : int32_t {
    OK = 0,
    INVALID_PARAM,
    INTERNAL_ERROR,
    OBJECT_RELEASED,
    SET_OBJECT_FAIL,
    GET_OBJECT_FAIL,
    GET_METHOD_FAIL,
    CALL_METHOD_FAIL,
};
class NotificationSubscriberExtension : public AbilityRuntime::ExtensionBase<NotificationSubscriberExtensionContext> {
public:
    NotificationSubscriberExtension() = default;
    virtual ~NotificationSubscriberExtension() = default;

    std::shared_ptr<NotificationSubscriberExtensionContext> CreateAndInitContext(
        const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
        const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
        std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
        const sptr<IRemoteObject>& token) override;

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
        const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
        std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
        const sptr<IRemoteObject>& token) override;

    static NotificationSubscriberExtension* Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

    virtual void OnDestroy();
    virtual NotificationSubscriberExtensionResult OnReceiveMessage(const std::shared_ptr<NotificationInfo> info);
    virtual NotificationSubscriberExtensionResult OnCancelMessages(
        const std::shared_ptr<std::vector<std::string>> hashCodes);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_SUBSCRIBER_EXTENSION_H