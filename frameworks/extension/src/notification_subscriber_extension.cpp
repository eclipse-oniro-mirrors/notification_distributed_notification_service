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

#include "notification_subscriber_extension.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
using namespace OHOS::AppExecFwk;
NotificationSubscriberExtension* NotificationSubscriberExtension::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    return new (std::nothrow) NotificationSubscriberExtension();
}

void NotificationSubscriberExtension::Init(const std::shared_ptr<AbilityLocalRecord>& record,
    const std::shared_ptr<OHOSApplication>& application,
    std::shared_ptr<AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    ANS_LOGD("Init");
    ExtensionBase<NotificationSubscriberExtensionContext>::Init(record, application, handler, token);
}

std::shared_ptr<NotificationSubscriberExtensionContext> NotificationSubscriberExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord>& record,
    const std::shared_ptr<OHOSApplication>& application,
    std::shared_ptr<AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    std::shared_ptr<NotificationSubscriberExtensionContext> context =
        ExtensionBase<NotificationSubscriberExtensionContext>::CreateAndInitContext(
            record, application, handler, token);
    if (record == nullptr) {
        ANS_LOGE("record is nullptr");
        return context;
    }
    return context;
}

void NotificationSubscriberExtension::OnDestroy()
{
    ANS_LOGD("OnDestroy called");
}

void NotificationSubscriberExtension::OnReceiveMessage(std::shared_ptr<NotificationInfo> info)
{
    ANS_LOGD("OnReceiveMessage called");
}

void NotificationSubscriberExtension::OnCancelMessages(std::shared_ptr<std::vector<std::string>> hashCodes)
{
    ANS_LOGD("OnCancelMessages called");
}

}  // namespace Notification
}  // namespace OHOS