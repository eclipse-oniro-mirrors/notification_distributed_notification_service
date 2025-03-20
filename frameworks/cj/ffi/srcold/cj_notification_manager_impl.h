/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NOTIFICATION_MANAGER_IMPL_H
#define NOTIFICATION_MANAGER_IMPL_H

#include "cj_notification_utils.h"
#include "ability_runtime/cj_ability_context.h"
namespace OHOS {
namespace CJSystemapi {
class NotificationManagerImpl {
public:
    static int Publish(CNotificationRequest cjRequest);
    static int Cancel(int32_t id, const char* label);
    static int CancelAll();
    static int AddSlot(int32_t type);
    static RetDataBool IsNotificationEnabled();
    static int SetBadgeNumber(int32_t badgeNumber);
    static int RequestEnableNotification();
    static int RequestEnableNotificationWithContext(sptr<AbilityRuntime::CJAbilityContext> context);
    static RetDataBool IsDistributedEnabled();
};
} // namespace CJSystemapi
} // namespace OHOS
#endif // NOTIFICATION_MANAGER_IMPL_H
