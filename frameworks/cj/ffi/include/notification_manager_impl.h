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

#include "notification_utils.h"
#include "ability_runtime/cj_ability_context.h"
namespace OHOS {
namespace CJSystemapi {
class NotificationManagerImplV2 {
public:
    static int Publish(CNotificationRequestV2 cjRequest);
    static int Cancel(int32_t id, const char* label);
    static int CancelAll();
    static int AddSlot(int32_t type);
    static CNotificationSlotV2 GetSlot(int32_t type, int32_t &errCode);
    static CArrayNotificationSlotsV2 GetSlots(int32_t &errCode);
    static int RemoveSlot(int32_t type);
    static int RemoveAllSlots();
    static RetDataUI32 GetActiveNotificationCount();
    static CArrayNotificationRequestV2 GetActiveNotifications(int32_t &errCode);
    static int CancelGroup(const char* cGroupName);
    static RetDataBool IsSupportTemplate(const char* cTemplateName);
    static int SetNotificationEnable(CNotificationBundleOptionV2 option, bool enable);
    static int DisplayBadge(CNotificationBundleOptionV2 option, bool enable);
    static RetDataBool IsBadgeDisplayed(CNotificationBundleOptionV2 option);
    static int SetSlotFlagsByBundle(CNotificationBundleOptionV2 option, int32_t slotFlags);
    static RetDataUI32 GetSlotFlagsByBundle(CNotificationBundleOptionV2 option);
    static RetDataUI32 GetSlotNumByBundle(CNotificationBundleOptionV2 option);
    static int RemoveGroupByBundle(CNotificationBundleOptionV2 option, const char* cGroupName);
    static RetDataBool IsNotificationEnabled();
    static int SetBadgeNumber(int32_t badgeNumber);
    static int RequestEnableNotification();
    static int RequestEnableNotificationWithContext(sptr<AbilityRuntime::CJAbilityContext> context);
    static RetDataBool IsDistributedEnabled();
};
} // namespace CJSystemapi
} // namespace OHOS
#endif // NOTIFICATION_MANAGER_IMPL_H
