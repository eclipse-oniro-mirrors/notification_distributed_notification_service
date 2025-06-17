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
static const char *REMOVE_FOR_BUNDLE_SIGNATURE =
    "Lnotification/NotificationCommonDef/BundleOption;"
    "L@ohos/notificationSubscribe/notificationSubscribe/NotificationKey;"
    "L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *REMOVE_FOR_HASHCODE_SIGNATURE =
    "Lstd/core/String;L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *REMOVE_FOR_HASHCODES_SIGNATURE =
    "Lescompat/Array;L@ohos/notificationSubscribe/notificationSubscribe/RemoveReason;:V";
static const char *DISTRIBUTE_OPERATION_SIGNATURE =
    "Lstd/core/String;L@ohos/notificationSubscribe/notificationSubscribe/OperationInfo;:Lstd/core/Promise;";
static const char *SUBSCRIBE_SIGNATURE =
   "Lnotification/notificationSubscriber/NotificationSubscriber;"
   "Lnotification/notificationSubscribeInfo/NotificationSubscribeInfo;:V";
static const char *UNSUBSCRIBE_SIGNATURE =
   "Lnotification/notificationSubscriber/NotificationSubscriber;:V";
static const char *REMOVEALL_FOR_BUNDLEOPTION_SIGNATURE =
   "Lnotification/NotificationCommonDef/BundleOption;:V";
static const char *REMOVEALL_FOR_USERID_STGNATURE = "D:V";
static const char *REMOVEALL_SIGNATURE = ":V";

ani_object AniDistributeOperation(ani_env *env, ani_string hashcode, ani_object operationInfo)
{
    ANS_LOGD("StsDistributeOperation enter");
    ani_object aniPromise {};
    ani_resolver aniResolver {};
    if (ANI_OK != env->Promise_New(&aniResolver, &aniPromise)) {
        ANS_LOGE("Promise_New faild");
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

void AniSubscribeSelf(ani_env *env, ani_object obj)
{
    ANS_LOGD("StsSubscribeSelf enter");
    OHOS::NotificationSts::SubscriberInstanceManager::GetInstance()->SubscribeSelf(env, obj);
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
        ani_native_function {"nativeRemove",
            REMOVE_FOR_BUNDLE_SIGNATURE, reinterpret_cast<void *>(AniRemoveForBundle)},
        ani_native_function {"nativeRemove",
            REMOVE_FOR_HASHCODE_SIGNATURE, reinterpret_cast<void *>(AniRemoveForHashCode)},
        ani_native_function {"nativeRemove",
            REMOVE_FOR_HASHCODES_SIGNATURE, reinterpret_cast<void *>(AniRemoveForHashCodes)},
        ani_native_function {"nativeDistributeOperation",
            DISTRIBUTE_OPERATION_SIGNATURE, reinterpret_cast<void *>(AniDistributeOperation)},
        ani_native_function {"nativeSubscribe", SUBSCRIBE_SIGNATURE, reinterpret_cast<void *>(AniSubscribe)},
        ani_native_function {"nativeUnSubscribe", UNSUBSCRIBE_SIGNATURE, reinterpret_cast<void *>(AniUnSubscribe)},
        ani_native_function {"nativeSubscribeSelf", UNSUBSCRIBE_SIGNATURE, reinterpret_cast<void *>(AniSubscribeSelf)},
        ani_native_function {"nativeRemoveAllForBundle",
            REMOVEALL_FOR_BUNDLEOPTION_SIGNATURE, reinterpret_cast<void *>(AniRemoveAllForBundle)},
        ani_native_function {"nativeRemoveAllForUserId",
            REMOVEALL_FOR_USERID_STGNATURE, reinterpret_cast<void *>(AniRemoveAllForUserId)},
        ani_native_function {"nativeRemoveAll", REMOVEALL_SIGNATURE, reinterpret_cast<void *>(AniRemoveAll)},
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