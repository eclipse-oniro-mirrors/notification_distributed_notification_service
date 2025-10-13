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

#include "notification_subscriber_extension_context.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "ability_business_error.h"
#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Notification {
const size_t NotificationSubscriberExtensionContext::CONTEXT_TYPE_ID(
    std::hash<const char*> {} ("NotificationSubscriberExtensionContext"));

NotificationSubscriberExtensionContext::NotificationSubscriberExtensionContext() {}

NotificationSubscriberExtensionContext::~NotificationSubscriberExtensionContext() {}

bool NotificationSubscriberExtensionContext::CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        ANS_LOGE("current app is not system app, not allow.");
        return false;
    }
    return true;
}

bool NotificationSubscriberExtensionContext::VerifyCallingPermission(const std::string& permissionName) const
{
    ANS_LOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        ANS_LOGE("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    ANS_LOGD("verify AccessToken success");
    return true;
}
}  // namespace Notification
}  // namespace OHOS