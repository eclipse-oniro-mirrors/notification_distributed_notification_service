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
#include "ani_notification_subscriber_extension.h"

#include <thread>
#include <iostream>
#include "ani_extension_subscription.h"
#include "ani_open_subscribe_settings.h"
#include "ans_log_wrapper.h"
#include "notification_helper.h"

namespace OHOS {
namespace NotificationExtensionSubScriptionSts {

void AniNotificationExtensionRegistryInit(ani_env *env)
{
    ANS_LOGD("AniNotificationExtensionRegistryInit call");
    static const char *npName = "@ohos.notificationExtensionSubscription.notificationExtensionSubscription";
    ani_namespace np;
    if (ANI_OK != env->FindNamespace(npName, &np)) {
        ANS_LOGD("Not found '%{public}s'", npName);
        return;
    }

    std::array methods = {
        ani_native_function {
            "nativeOpenSubscriptionSettings", nullptr, reinterpret_cast<void*>(AniOpenSubscribeSettings) },
        ani_native_function { "nativeSubscribe", nullptr, reinterpret_cast<void*>(AniSubscribe) },
        ani_native_function { "nativeUnsubscribe", nullptr, reinterpret_cast<void*>(AniUnsubscribe) },
        ani_native_function { "nativeGetSubscribeInfo", nullptr, reinterpret_cast<void*>(AniGetSubscribeInfo) },
        ani_native_function {
            "nativeGetAllSubscriptionBundles", nullptr, reinterpret_cast<void*>(AniGetAllSubscriptionBundles) },
        ani_native_function { "nativeIsUserGranted", nullptr, reinterpret_cast<void*>(AniIsUserGranted) },
        ani_native_function { "nativeGetUserGrantedState", nullptr, reinterpret_cast<void*>(AniGetUserGrantedState) },
        ani_native_function { "nativeSetUserGrantedState", nullptr, reinterpret_cast<void*>(AniSetUserGrantedState) },
        ani_native_function {
            "nativeGetUserGrantedEnabledBundles", nullptr, reinterpret_cast<void*>(AniGetUserGrantedEnabledBundles) },
        ani_native_function { "nativeGetUserGrantedEnabledBundlesForSelf", nullptr,
            reinterpret_cast<void*>(AniGetUserGrantedEnabledBundlesForSelf) },
        ani_native_function {
            "nativeSetUserGrantedBundleState", nullptr, reinterpret_cast<void*>(AniSetUserGrantedBundleState) },
    };

    ANS_LOGD("Start bind native methods to '%{public}s'", npName);
    ani_status status = env->Namespace_BindNativeFunctions(np, methods.data(), methods.size());
    if (ANI_OK != status) {
        ANS_LOGD("Cannot bind native methods to '%{public}s'. status %{public}d", npName, status);
        return;
    };
    ANS_LOGD("Finish bind native methods to '%{public}s'", npName);

    if (env->ResetError() != ANI_OK) {
        ANS_LOGD("ResetError failed");
    }
    ANS_LOGD("AniNotificationExtensionRegistryInit end");
}
} // namespace NotificationExtensionSubScriptionSts
} // namespace OHOS

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ANS_LOGD("ANI_Constructor enter");
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ANS_LOGD("Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }

    OHOS::NotificationExtensionSubScriptionSts::AniNotificationExtensionRegistryInit(env);
    ANS_LOGD("ANI_Constructor OK");
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}