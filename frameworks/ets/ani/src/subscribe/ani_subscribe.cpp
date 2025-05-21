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
#include "ani_subscribe.h"

#include <thread>
#include <iostream>
#include "inner_errors.h"
#include "notification_helper.h"
#include "ani_remove.h"
#include "ans_log_wrapper.h"
#include "sts_subscribe.h"

namespace OHOS {
namespace NotificationSubScribeSts {
static const char *cRemoveForBundleSignature =
    "Lnotification/NotificationCommonDef/BundleOption;"
    "L@ohos/notificationSubscribe/notificationSubscribe/NotificationKey;"
    "L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *cRemoveForHashCodeSignature =
    "Lstd/core/String;L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *cRemoveForHashCodesSignature =
    "Lescompat/Array;L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *cDistributeOperationSignature =
    "Lstd/core/String;L@ohos/notificationSubscribe/notificationSubscribe/OperationInfo;:Lstd/core/Promise;";
static const char *cSubscribeSignature =
   "Lnotification/notificationSubscriber/NotificationSubscriber;"
   "Lnotification/notificationSubscribeInfo/NotificationSubscribeInfo;:V";
static const char *cUnSubscribeSignature =
   "Lnotification/notificationSubscriber/NotificationSubscriber;:V";

ani_object AniDistributeOperation(ani_env *env, ani_string hashcode, ani_object operationInfo)
{
    ANS_LOGD("StsDistributeOperation enter");
    ani_object aniPromise {};
    ani_resolver aniResolver {};
    if (ANI_OK != env->Promise_New(&aniResolver, &aniPromise)) {
        ANS_LOGD("Promise_New faild");
        return nullptr;
    }
    bool noWithOperationInfo = false;
    auto info = NotificationSts::GetOperationInfoForDistributeOperation(
        env, hashcode, operationInfo, noWithOperationInfo);
    if (info == nullptr) {
        ANS_LOGE("get distributeOperation object fail");
        return nullptr;
    }
    sptr<NotificationSts::StsDistributedOperationCallback> callback 
        = new (std::nothrow) NotificationSts::StsDistributedOperationCallback(aniPromise, aniResolver);
    if (callback == nullptr) {
        ANS_LOGE("create callback object fail");
        return nullptr;
    }

    ani_vm *vm = nullptr;
    if (ANI_OK != env->GetVM(&vm)) {
        ANS_LOGD("env GetVM faild");
        return nullptr;
    }
    callback->SetVm(vm);
    int32_t result = Notification::NotificationHelper::DistributeOperation(info, callback);
    ANS_LOGD("StsDistributeOperation ret %{public}d. ErrorToExternal %{public}d",
        result, CJSystemapi::Notification::ErrorToExternal(result));
    if (result != ERR_OK || noWithOperationInfo) {
        callback->OnStsOperationCallback(env, result);
    }
    return aniPromise;
}

void AniSubscribe(ani_env *env, ani_object obj, ani_object info)
{
    ANS_LOGD("StsSubscribe enter");
    OHOS::NotificationSts::SubscriberInstanceManager::GetInstance()->Subscribe(env, obj, info);
}

void AniUnSubscribe(ani_env *env, ani_object obj)
{
    ANS_LOGD("StsUnSubscribe enter");
    OHOS::NotificationSts::SubscriberInstanceManager::GetInstance()->UnSubscribe(env, obj);
}

void AniSubScribeRegistryInit(ani_env *env)
{
    ANS_LOGD("AniSubScribeRegistryInit call");
    static const char *npName = "L@ohos/notificationSubscribe/notificationSubscribe;";
    ani_namespace np;
    if (ANI_OK != env->FindNamespace(npName, &np)) {
        ANS_LOGD("Not found '%{public}s'", npName);
        return;
    }

    std::array methods = {
        ani_native_function {"nativeRemove", cRemoveForBundleSignature, reinterpret_cast<void *>(AniRemoveForBundle)},
        ani_native_function {"nativeRemove",
            cRemoveForHashCodeSignature, reinterpret_cast<void *>(AniRemoveForHashCode)},
        ani_native_function {"nativeRemove",
            cRemoveForHashCodesSignature, reinterpret_cast<void *>(AniRemoveForHashCodes)},
        ani_native_function {"nativeDistributeOperation",
            cDistributeOperationSignature, reinterpret_cast<void *>(AniDistributeOperation)},
        ani_native_function {"nativeSubscribe", cSubscribeSignature, reinterpret_cast<void *>(AniSubscribe)},
        ani_native_function {"nativeUnSubscribe", cUnSubscribeSignature, reinterpret_cast<void *>(AniUnSubscribe)},
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
    ANS_LOGD("AniSubScribeRegistryInit end");
}
} // namespace NotificationSubScribeSts
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

    OHOS::NotificationSubScribeSts::AniSubScribeRegistryInit(env);
    ANS_LOGD("ANI_Constructor OK");
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}