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
#include "ani_manager.h"

#include "ans_log_wrapper.h"
#include "ani_display_badge.h"
#include "ani_slot.h"
#include "ani_cance.h"
#include "ani_notification_enable.h"
#include "ani_do_not_disturb_profile.h"
#include "ani_get_active.h"
#include "ani_publish.h"
#include "ani_local_live_view.h"
#include "ani_request_enable.h"

namespace OHOS {
namespace NotificationManagerSts {

void AniNotificationManagerRegistryInit(ani_env *env)
{
    ANS_LOGD("StsNotificationManagerRegistryInit call");
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        ANS_LOGD("ResetError failed");
    }
    ani_namespace ns;
    status = env->FindNamespace("L@ohos/notificationManager/notificationManager;", &ns);
    if (status != ANI_OK) {
        ANS_LOGE("FindNamespace notificationManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {
        ani_native_function {"nativeCancelAll", nullptr, reinterpret_cast<void *>(AniCancelAll)},
        // ani_native_function {"nativeGetActiveNotifications", nullptr, reinterpret_cast<void *>(AniCancelWithIdOptinalLabel)},
        ani_native_function {"nativeCancelWithId", nullptr, reinterpret_cast<void *>(AniCancelWithId)},
        ani_native_function {"nativeCancelWithIdLabel", nullptr, reinterpret_cast<void *>(AniCancelWithIdLabel)},
        ani_native_function {"nativeCancelWithBundle", nullptr, reinterpret_cast<void *>(AniCancelWithBundle)},

        ani_native_function {"nativeDisplayBadge", nullptr, reinterpret_cast<void *>(AniDisplayBadge)},
        ani_native_function {"nativeIsBadgeDisplayed", nullptr, reinterpret_cast<void *>(AniIsBadgeDisplayed)},

        ani_native_function {"nativeGetActiveNotificationCount", ":D",
            reinterpret_cast<void *>(AniGetActiveNotificationCount)},
        ani_native_function {"nativeGetActiveNotifications", nullptr,
            reinterpret_cast<void *>(AniGetActiveNotifications)},
        ani_native_function {"nativeGetAllActiveNotifications", nullptr,
            reinterpret_cast<void *>(AniGetAllActiveNotifications)},

        ani_native_function {"nativeAddDoNotDisturbProfile", nullptr,
            reinterpret_cast<void *>(AniAddDoNotDisturbProfile)},
        ani_native_function {"nativeRemoveDoNotDisturbProfile", nullptr,
            reinterpret_cast<void *>(AniRemoveDoNotDisturbProfile)},

        ani_native_function {"nativeSubscribeSystemLiveView", nullptr,
            reinterpret_cast<void *>(AniSubscribeSystemLiveView)},
        ani_native_function {"nativeTriggerSystemLiveView", nullptr,
            reinterpret_cast<void *>(AniTriggerSystemLiveView)},

        ani_native_function {"nativePublishWithUserId", nullptr, reinterpret_cast<void *>(AniPublishWithId)},
        ani_native_function {"nativePublish", nullptr, reinterpret_cast<void *>(AniPublish)},

        ani_native_function {"nativeGetSlotFlagsByBundle", nullptr, reinterpret_cast<void *>(AniGetSlotFlagsByBundle)},
        ani_native_function {"nativeSetSlotFlagsByBundle", nullptr, reinterpret_cast<void *>(AniSetSlotFlagsByBundle)},
        ani_native_function {"nativeGetSlotsByBundle", nullptr, reinterpret_cast<void *>(AniGetSlotsByBundle)},

        ani_native_function {"nativeIsNotificationSlotEnabled", nullptr,
            reinterpret_cast<void *>(AniIsNotificationSlotEnabled)},
        ani_native_function {"nativeSetNotificationEnableSlot", nullptr,
            reinterpret_cast<void *>(AniSetNotificationEnableSlot)},
        ani_native_function {"nativeSetNotificationEnableSlotWithForce", nullptr,
            reinterpret_cast<void *>(AniSetNotificationEnableSlotWithForce)},

        ani_native_function {"nativeIsNotificationEnabled", nullptr,
            reinterpret_cast<void *>(AniIsNotificationEnabled)},
        ani_native_function {"nativeIsNotificationEnabledWithId", nullptr,
            reinterpret_cast<void *>(AniIsNotificationEnabledWithId)},
        ani_native_function {"nativeIsNotificationEnabledWithBundleOption", nullptr,
            reinterpret_cast<void *>(AniIsNotificationEnabledWithBundleOption)},
        ani_native_function {"nativeSetNotificationEnable",
            nullptr, reinterpret_cast<void *>(AniSetNotificationEnable)},
        ani_native_function {"nativeRequestEnableNotification",
            "Lapplication/UIAbilityContext/UIAbilityContext;:Lstd/core/Promise;",
            reinterpret_cast<void *>(AniRequestEnableNotification)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        ANS_LOGD("Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        ANS_LOGD("ResetError failed");
    }
    ANS_LOGD("StsNotificationManagerRegistryInit end");
}
} // namespace NotificationManagerSts
} // namespace OHOS

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ANS_LOGD("ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        ANS_LOGE("GetEnv failed status : %{public}d", status);
        return ANI_NOT_FOUND;
    }

    OHOS::NotificationManagerSts::AniNotificationManagerRegistryInit(env);
    *result = ANI_VERSION_1;
    ANS_LOGD("ANI_Constructor finish");
    return ANI_OK;
}
}