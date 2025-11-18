/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "ans_log_wrapper.h"
#include "constant.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_cancel.h"
#include "napi_disable_notification.h"
#include "napi_display_badge.h"
#include "napi_distributed.h"
#include "napi_disturb_mode.h"
#include "napi_priority.h"
#include "napi_enable_notification.h"
#include "napi_geofence_enabled.h"
#include "napi_get_active.h"
#include "napi_publish.h"
#include "napi_remove_group.h"
#include "napi_ringtone_info_by_bundle.h"
#include "napi_slot.h"
#include "napi_template.h"
#include "pixel_map_napi.h"
#include "napi_push.h"
#include "napi_local_live_view.h"
#include "napi_distributed_enable.h"
#include "napi_sync_config.h"
#include "napi_open_settings.h"
#include "napi_silent_reminder_enable.h"
#include "napi_reminder_info.h"
#include "napi_badge_query_callback.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

EXTERN_C_START

static napi_value NapiPushInit(napi_env env, napi_value exports)
{
    ANS_LOGD("called");
    if (env == nullptr || exports == nullptr) {
        ANS_LOGE("null env or exports");
        return nullptr;
    }

    std::unique_ptr<NapiPush> napiPush = std::make_unique<NapiPush>();
    napi_wrap(env, exports, napiPush.release(), NapiPush::Finalizer, nullptr, nullptr);

    const char *moduleName = "NapiPush";
#ifdef ANS_FEATURE_LIVEVIEW_LOCAL_LIVEVIEW
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "on", moduleName, NapiPush::RegisterPushCallback);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "off", moduleName, NapiPush::UnregisterPushCallback);
#else
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "on", moduleName, Common::NapiReturnCapErr);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "off", moduleName, Common::NapiReturnCapErr);
#endif
    return exports;
}

napi_value NotificationManagerInit(napi_env env, napi_value exports)
{
    ANS_LOGD("called");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("publish", NapiPublish),
        DECLARE_NAPI_FUNCTION("publishAsBundle", NapiPublishAsBundle),
        DECLARE_NAPI_FUNCTION("show", NapiShowNotification),
        DECLARE_NAPI_FUNCTION("cancel", NapiCancel),
        DECLARE_NAPI_FUNCTION("cancelAll", NapiCancelAll),
        DECLARE_NAPI_FUNCTION("cancelGroup", NapiCancelGroup),
        DECLARE_NAPI_FUNCTION("cancelAsBundle", NapiCancelAsBundle),
        DECLARE_NAPI_FUNCTION("removeGroupByBundle", NapiRemoveGroupByBundle),
        DECLARE_NAPI_FUNCTION("addSlot", NapiAddSlot),
        DECLARE_NAPI_FUNCTION("addSlots", NapiAddSlots),
        DECLARE_NAPI_FUNCTION("getSlot", NapiGetSlot),
        DECLARE_NAPI_FUNCTION("getSlots", NapiGetSlots),
        DECLARE_NAPI_FUNCTION("removeSlot", NapiRemoveSlot),
        DECLARE_NAPI_FUNCTION("removeAllSlots", NapiRemoveAllSlots),
        DECLARE_NAPI_FUNCTION("getAllNotificationEnabledBundles", NapiGetAllNotificationEnabledBundles),
        DECLARE_NAPI_FUNCTION("setNotificationEnable", NapiEnableNotification),
        DECLARE_NAPI_FUNCTION("isNotificationEnabled", NapiIsNotificationEnabled),
        DECLARE_NAPI_FUNCTION("getAllActiveNotifications", NapiGetAllActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotifications", NapiGetActiveNotifications),
        DECLARE_NAPI_FUNCTION("getActiveNotificationCount", NapiGetActiveNotificationCount),
        DECLARE_NAPI_FUNCTION("getActiveNotificationByFilter", NapiGetActiveNotificationByFilter),
        DECLARE_NAPI_FUNCTION("isSupportTemplate", NapiIsSupportTemplate),
        DECLARE_NAPI_FUNCTION("getSyncNotificationEnabledWithoutApp", NapiGetSyncNotificationEnabledWithoutApp),
        DECLARE_NAPI_FUNCTION("isNotificationEnabledSync", NapiIsNotificationEnabledSync),
        DECLARE_NAPI_FUNCTION("setDistributedEnabledBySlot", NapiSetDistributedEnabledBySlot),
        DECLARE_NAPI_FUNCTION("isDistributedEnabledBySlot", NapiIsDistributedEnabledBySlot),
        DECLARE_NAPI_FUNCTION("disableNotificationFeature", NapiDisableNotificationFeature),
        DECLARE_NAPI_FUNCTION("setTargetDeviceStatus", NapiSetTargetDeviceStatus),
        DECLARE_NAPI_FUNCTION("requestEnableNotification", NapiRequestEnableNotification),
        DECLARE_NAPI_FUNCTION("getNotificationSetting", NapiGetNotificationSettings),
        DECLARE_NAPI_FUNCTION("setSilentReminderEnabled", NapiSetSilentReminderEnabled),
        DECLARE_NAPI_FUNCTION("isSilentReminderEnabled", NapiIsSilentReminderEnabled),
        DECLARE_NAPI_FUNCTION("setRingtoneInfoByBundle", NapiSetRingtoneInfoByBundle),
        DECLARE_NAPI_FUNCTION("getRingtoneInfoByBundle", NapiGetRingtoneInfoByBundle),
        DECLARE_NAPI_FUNCTION("getReminderInfoByBundles", NapiGetReminderInfoByBundles),
        DECLARE_NAPI_FUNCTION("setGeofenceEnabled", NapiSetGeofenceEnabled),
        DECLARE_NAPI_FUNCTION("isGeofenceEnabled", NapiIsGeofenceEnabled),
        DECLARE_NAPI_FUNCTION("setReminderInfoByBundles", NapiSetReminderInfoByBundles),

#ifdef ANS_FEATURE_BADGE_MANAGER
        DECLARE_NAPI_FUNCTION("displayBadge", NapiDisplayBadge),
        DECLARE_NAPI_FUNCTION("isBadgeDisplayed", NapiIsBadgeDisplayed),
        DECLARE_NAPI_FUNCTION("getBadgeNumber", NapiGetBadgeNumber),
        DECLARE_NAPI_FUNCTION("setBadgeNumber", NapiSetBadgeNumber),
        DECLARE_NAPI_FUNCTION("setBadgeNumberByBundle", NapiSetBadgeNumberByBundle),
        DECLARE_NAPI_FUNCTION("setBadgeDisplayStatusByBundles", NapiSetBadgeDisplayStatusByBundles),
        DECLARE_NAPI_FUNCTION("getBadgeDisplayStatusByBundles", NapiGetBadgeDisplayStatusByBundles),
        DECLARE_NAPI_FUNCTION("onBadgeNumberQuery", NapiOnBadgeNumberQuery),
        DECLARE_NAPI_FUNCTION("offBadgeNumberQuery", NapiOffBadgeNumberQuery),
#else
        DECLARE_NAPI_FUNCTION("displayBadge", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isBadgeDisplayed", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getBadgeNumber", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setBadgeNumber", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setBadgeNumberByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getBadgeDisplayStatusByBundles", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setBadgeDisplayStatusByBundles", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("onBadgeNumberQuery", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("offBadgeNumberQuery", Common::NapiReturnCapErrCb),

#endif

#ifdef ANS_FEATURE_DISTRIBUTED_DB
        DECLARE_NAPI_FUNCTION("isDistributedEnabled", NapiIsDistributedEnabled),
        DECLARE_NAPI_FUNCTION("setDistributedEnable", NapiEnableDistributed),
        DECLARE_NAPI_FUNCTION("setDistributedEnableByBundle", NapiEnableDistributedByBundle),
        DECLARE_NAPI_FUNCTION("enableDistributedSelf", NapiEnableDistributedSelf),
        DECLARE_NAPI_FUNCTION("isDistributedEnabledByBundle", NapiIsDistributedEnableByBundle),
        DECLARE_NAPI_FUNCTION("setDistributedEnabledByBundle", NapiSetDistributedEnabledByBundle),
        DECLARE_NAPI_FUNCTION("setDistributedEnableByBundles", NapiSetDistributedBundleOption),
        DECLARE_NAPI_FUNCTION("setSmartReminderEnabled", NapiSetSmartReminderEnabled),
        DECLARE_NAPI_FUNCTION("getDeviceRemindType", NapiGetDeviceRemindType),
        DECLARE_NAPI_FUNCTION("setSyncNotificationEnabledWithoutApp", NapiSetSyncNotificationEnabledWithoutApp),
        DECLARE_NAPI_FUNCTION("isSmartReminderEnabled", NapiIsSmartReminderEnabled),
        DECLARE_NAPI_FUNCTION("setDistributedEnabled", NapiSetDistributedEnabled),
        DECLARE_NAPI_FUNCTION("getDistributedDeviceList", NapiGetDistributedDeviceList),
#else
        DECLARE_NAPI_FUNCTION("isDistributedEnabled", Common::NapiReturnFalseCbNewType),
        DECLARE_NAPI_FUNCTION("setDistributedEnable", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setDistributedEnableByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("enableDistributedSelf", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isDistributedEnabledByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setDistributedEnabledByBundle", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("setDistributedEnableByBundles", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("setSmartReminderEnabled", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("getDeviceRemindType", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setSyncNotificationEnabledWithoutApp", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isSmartReminderEnabled", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("setDistributedEnabled", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("getDistributedDeviceList", Common::NapiReturnCapErr),
#endif
        
#ifdef ANS_FEATURE_DISTURB_MANAGER
        DECLARE_NAPI_FUNCTION("setDoNotDisturbDate", NapiSetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbDate", NapiGetDoNotDisturbDate),
        DECLARE_NAPI_FUNCTION("addDoNotDisturbProfile", NapiAddDoNotDisturbProfiles),
        DECLARE_NAPI_FUNCTION("removeDoNotDisturbProfile", NapiRemoveDoNotDisturbProfiles),
        DECLARE_NAPI_FUNCTION("supportDoNotDisturbMode", NapiSupportDoNotDisturbMode),
        DECLARE_NAPI_FUNCTION("isSupportDoNotDisturbMode", NapiSupportDoNotDisturbMode),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbProfile", NapiGetDoNotDisturbProfile),
#else
        DECLARE_NAPI_FUNCTION("setDoNotDisturbDate", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbDate", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("addDoNotDisturbProfile", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("removeDoNotDisturbProfile", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("supportDoNotDisturbMode", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isSupportDoNotDisturbMode", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getDoNotDisturbProfile", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_SLOT_MANAGER
        DECLARE_NAPI_FUNCTION("setSlotByBundle", NapiSetSlotByBundle),
        DECLARE_NAPI_FUNCTION("getSlotsByBundle", NapiGetSlotsByBundle),
        DECLARE_NAPI_FUNCTION("setNotificationEnableSlot", NapiEnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("isNotificationSlotEnabled", NapiIsEnableNotificationSlot),
        DECLARE_NAPI_FUNCTION("setSlotFlagsByBundle", NapiSetSlotFlagsByBundle),
        DECLARE_NAPI_FUNCTION("getSlotFlagsByBundle", NapiGetSlotFlagsByBundle),
        DECLARE_NAPI_FUNCTION("getSlotByBundle", NapiGetSlotByBundle),
        DECLARE_NAPI_FUNCTION("getSlotNumByBundle", NapiGetSlotNumByBundle),
#else
        DECLARE_NAPI_FUNCTION("setSlotByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotsByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setNotificationEnableSlot", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("isNotificationSlotEnabled", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("setSlotFlagsByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotFlagsByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotByBundle", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("getSlotNumByBundle", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_LIVEVIEW_LOCAL_LIVEVIEW
        DECLARE_NAPI_FUNCTION("subscribeSystemLiveView", NapiSubscriteLocalAcitvity),
        DECLARE_NAPI_FUNCTION("triggerSystemLiveView", NapiTriggerLocalLiveView),
#else
        DECLARE_NAPI_FUNCTION("subscribeSystemLiveView", Common::NapiReturnCapErrCb),
        DECLARE_NAPI_FUNCTION("triggerSystemLiveView", Common::NapiReturnCapErrCb),
#endif

#ifdef ANS_FEATURE_ADDITIONAL_CONFIG
        DECLARE_NAPI_FUNCTION("setAdditionalConfig", NapiSetAdditionConfig),
#else
        DECLARE_NAPI_FUNCTION("setAdditionalConfig", Common::NapiReturnCapErr),
#endif

#ifdef ANS_FEATURE_OPEN_NOTIFICATION_SETTINGS
        DECLARE_NAPI_FUNCTION("openNotificationSettings", NapiOpenNotificationSettings),
#else
        DECLARE_NAPI_FUNCTION("openNotificationSettings", Common::NapiReturnCapErr),
#endif

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        DECLARE_NAPI_FUNCTION("setPriorityEnabled", NapiSetPriorityEnabled),
        DECLARE_NAPI_FUNCTION("setPriorityEnabledByBundle", NapiSetPriorityEnabledByBundle),
        DECLARE_NAPI_FUNCTION("isPriorityEnabled", NapiIsPriorityEnabled),
        DECLARE_NAPI_FUNCTION("isPriorityEnabledByBundle", NapiIsPriorityEnabledByBundle),
        DECLARE_NAPI_FUNCTION("setBundlePriorityConfig", NapiSetBundlePriorityConfig),
        DECLARE_NAPI_FUNCTION("getBundlePriorityConfig", NapiGetBundlePriorityConfig),
#else
        DECLARE_NAPI_FUNCTION("setPriorityEnabled", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("setPriorityEnabledByBundle", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("isPriorityEnabled", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("isPriorityEnabledByBundle", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("setBundlePriorityConfig", Common::NapiReturnCapErr),
        DECLARE_NAPI_FUNCTION("getBundlePriorityConfig", Common::NapiReturnCapErr),
#endif
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return NapiPushInit(env, exports);
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
