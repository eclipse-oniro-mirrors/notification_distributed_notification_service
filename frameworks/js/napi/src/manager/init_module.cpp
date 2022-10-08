/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "init_module.h"
#include "constant.h"
#include "napi_cancel.h"
#include "napi_display_badge.h"
#include "napi_distributed.h"
#include "napi_disturb_mode.h"
#include "napi_enable_notification.h"
#include "napi_get_active.h"
#include "napi_publish.h"
#include "napi_slot.h"
#include "napi_template.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

EXTERN_C_START

napi_value NotificationManagerInit(napi_env env, napi_value exports)
{
    ANS_LOGI("NotificationManagerInit start");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("publish", Napi_Publish),
        DECLARE_NAPI_FUNCTION("publishAsBundle", Napi_PublishAsBundle),
        DECLARE_NAPI_FUNCTION("show", Napi_ShowNotification),
        DECLARE_NAPI_FUNCTION("cancel", Napi_Cancel),
        DECLARE_NAPI_FUNCTION("cancelAll", Napi_CancelAll),
        DECLARE_NAPI_FUNCTION("cancelGroup", Napi_CancelGroup),
        DECLARE_NAPI_FUNCTION("cancelAsBundle", Napi_CancelAsBundle),
        DECLARE_NAPI_FUNCTION("addSlot", Napi_AddSlot),
        DECLARE_NAPI_FUNCTION("addSlots", Napi_AddSlots),
        DECLARE_NAPI_FUNCTION("setSlotByBundle", Napi_SetSlotByBundle),
        DECLARE_NAPI_FUNCTION("getSlot", Napi_GetSlot),
        DECLARE_NAPI_FUNCTION("getSlotNumByBundle", Napi_GetSlotNumByBundle),
        DECLARE_NAPI_FUNCTION("getSlots", Napi_GetSlots),
        DECLARE_NAPI_FUNCTION("getSlotsByBundle", Napi_GetSlotsByBundle),
        DECLARE_NAPI_FUNCTION("removeSlot", Napi_RemoveSlot),
        DECLARE_NAPI_FUNCTION("removeAllSlots", Napi_RemoveAllSlots),
        DECLARE_NAPI_FUNCTION("setNotificationEnableSlot", Napi_EnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("isNotificationSlotEnabled", Napi_IsEnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("setNotificationEnable", Napi_EnableNotification),
        DECLARE_NAPI_FUNCTION("isNotificationEnabled", Napi_IsNotificationEnabled),
        DECLARE_NAPI_FUNCTION("requestEnableNotification", Napi_RequestEnableNotification),
        DECLARE_NAPI_FUNCTION("getAllActiveNotifications", Napi_GetAllActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotifications", Napi_GetActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotificationCount", Napi_GetActiveNotificationCount),
        DECLARE_NAPI_FUNCTION("displayBadge", Napi_DisplayBadge),
        DECLARE_NAPI_FUNCTION("isBadgeDisplayed", Napi_IsBadgeDisplayed),
        DECLARE_NAPI_FUNCTION("setDoNotDisturbDate", Napi_SetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbDate", Napi_GetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("supportDoNotDisturbMode", Napi_SupportDoNotDisturbMode),
        DECLARE_NAPI_FUNCTION("isSupportTemplate", Napi_IsSupportTemplate),
        DECLARE_NAPI_FUNCTION("isDistributedEnabled", Napi_IsDistributedEnabled),
        DECLARE_NAPI_FUNCTION("setDistributedEnable", Napi_EnableDistributed),
        DECLARE_NAPI_FUNCTION("setDistributedEnableByBundle", Napi_EnableDistributedByBundle),
        DECLARE_NAPI_FUNCTION("enableDistributedSelf", Napi_EnableDistributedSelf),
        DECLARE_NAPI_FUNCTION("isDistributedEnableByBundle", Napi_IsDistributedEnableByBundle),
        DECLARE_NAPI_FUNCTION("getDeviceRemindType", Napi_GetDeviceRemindType),
        DECLARE_NAPI_FUNCTION("setSyncNotificationEnabledWithoutApp", Napi_SetSyncNotificationEnabledWithoutApp),
        DECLARE_NAPI_FUNCTION("getSyncNotificationEnabledWithoutApp", Napi_GetSyncNotificationEnabledWithoutApp),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}

/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    /*
     * Propertise define
     */
    NotificationManagerInit(env, exports);
    ConstantInit(env, exports);
    OHOS::Media::PixelMapNapi::Init(env, exports);

    return exports;
}

/*
 * Module register function
 */
__attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module_manager);
}
EXTERN_C_END
}  // namespace NotificationNapi
}  // namespace OHOS