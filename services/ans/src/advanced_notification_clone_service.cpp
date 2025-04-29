/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "advanced_notification_service.h"

#include "notification_clone_manager.h"
namespace OHOS {
namespace Notification {

constexpr int32_t INVALID_FD_NUM = -1;
constexpr int32_t PERMISSION_NUM = 0660;
constexpr const char *EXTENSION_SUCCESS = "notification extension success";

int32_t AdvancedNotificationService::OnBackup(MessageParcel& data, MessageParcel& reply)
{
    return NotificationCloneManager::GetInstance().OnBackup(data, reply);
}

int32_t AdvancedNotificationService::OnRestore(MessageParcel& data, MessageParcel& reply)
{
// todo double to single
    return NotificationCloneManager::GetInstance().OnRestore(data, reply);
}
}  // namespace Notification
}  // namespace OHOS
