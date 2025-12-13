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
#include "sts_notification_subscriber_extension_context.h"

#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "ets_extension_context.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationSts {
namespace {
constexpr const char* NOTIFICATION_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME =
"@ohos.application.NotificationSubscriberExtensionContext.NotificationSubscriberExtensionContext";
}

static void StartAbility([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object aniObj, ani_object wantObj)
{
    ANS_LOGD("StartAbility");
}

ani_object CreateNotificationSubscriberExtensionContext(ani_env *env,
    std::shared_ptr<NotificationSubscriberExtensionContext> context,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application)
{
    if (env == nullptr) {
        ANS_LOGE("null env");
        return nullptr;
    }
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    ani_class cls = nullptr;
    ani_object contextObj = nullptr;
    ani_field field = nullptr;
    ani_method method = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(NOTIFICATION_SUBSCRIBER_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        ANS_LOGE("find class status : %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "", "C{@ohos.app.ability.Want.Want}:",
            reinterpret_cast<void*>(StartAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        ANS_LOGE("bind method status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        ANS_LOGE("find Method status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        ANS_LOGE("new Object status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeNotificationSubscriberExtensionContext", &field)) != ANI_OK) {
        ANS_LOGE("find field status: %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        ANS_LOGE("set field status: %{public}d", status);
        return nullptr;
    }
    if (application == nullptr) {
        ANS_LOGE("application null");
        return nullptr;
    }
    OHOS::AbilityRuntime::CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}
}
}