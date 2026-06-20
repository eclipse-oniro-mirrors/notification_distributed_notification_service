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
#include "ani_distributed_enable.h"

#include "ans_notification.h"
#include "singleton.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
using namespace OHOS::Notification;
using OHOS::Notification::AnsNotification;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackDistributedInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackDistributedInfo Without Promise");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.callback != nullptr) {
        ANS_LOGD("Delete callback reference");
        ani_status status = env->GlobalReference_Delete(asyncCallbackInfo->info.callback);
        if (status != ANI_OK) {
            ANS_LOGW("GlobalReference_Delete failed, status: %{public}d", status);
        }
    }
    if (asyncCallbackInfo->asyncWork != nullptr) {
        ANS_LOGD("DeleteAsyncWork");
        DeleteAsyncWork(env, asyncCallbackInfo->asyncWork);
        asyncCallbackInfo->asyncWork = nullptr;
    }
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

void DeleteCallBackInfo(ani_env* env, AsyncCallbackDistributedInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackDistributedInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        ani_status status = env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
        if (status != ANI_OK) {
            ANS_LOGW("GlobalReference_Delete failed, status: %{public}d", status);
        }
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackDistributedInfo* asyncCallbackInfo)
{
    if (!NotificationSts::IsUndefine(env, callback)) {
        ani_ref globalRef;
        if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &globalRef) != ANI_OK) {
            NotificationSts::ThrowInternerErrorWithLogE(env, "create callback ref failed");
            return false;
        }
        asyncCallbackInfo->info.callback = globalRef;
    }
    return true;
}

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackDistributedInfo* asyncCallbackInfo)
{
    if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, envCurr) != ANI_OK || envCurr == nullptr) {
        ANS_LOGE("GetEnv failed");
        return false;
    }
    if (asyncCallbackInfo->info.returnCode != ERR_OK) {
        ANS_LOGE("return ErrCode: %{public}d", asyncCallbackInfo->info.returnCode);
        NotificationSts::CreateReturnData(*envCurr, asyncCallbackInfo->info);
        DeleteCallBackInfoWithoutPromise(*envCurr, asyncCallbackInfo);
        return false;
    }
    return true;
}

void HandleDistribCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case IS_DISTURB_ENABLED:
        case IS_DISTURB_ENABLED_BY_BUNDLE:
        case IS_DISTURB_ENABLED_BY_BUNDLE_TYPE:
        case IS_DISTURB_ENABLED_BY_SLOT:
        case IS_DISTURB_ENABLED_BY_DEVICE_TYPE:
        case IS_SMART_REMINDER_ENABLE: {
            asyncCallbackInfo->info.result =
                NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->isEnabled);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isEnabled failed");
                asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
            }
            break;
        }
        case GET_DISTURB_ENABLED_DEVICE_LIST: {
            asyncCallbackInfo->info.result = NotificationSts::GetAniStringArrayByVectorString(
                envCurr, asyncCallbackInfo->deviceList);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("GetAniStringArrayByVectorString for deviceList failed");
                asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
            }
            break;
        }
        default:
            break;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniIsDistributedEnabled(ani_env* env, ani_object callback)
{
    ANS_LOGD("AniIsDistributedEnabled called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_DISTURB_ENABLED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(
                        asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniIsDistributedEnabledByBundle(ani_env* env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniIsDistributedEnabledByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed!");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_DISTURB_ENABLED_BY_BUNDLE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnableByBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniIsDistributedEnabledByBundleType(ani_env* env, ani_object obj, ani_string deviceType,
    ani_object callback)
{
    ANS_LOGD("AniIsDistributedEnabledByBundleType called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed!");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    std::string deviceTypeStr;
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "deviceType parse failed!");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_DISTURB_ENABLED_BY_BUNDLE_TYPE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            int32_t enabled = 0;
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledByBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->deviceTypeStr, true, enabled);
                asyncCallbackInfo->isEnabled =
                (enabled == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ||
                enabled == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON));
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnable(ani_env* env, ani_boolean enabled, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnable called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enabled);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributed(
                        asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnableByBundle(ani_env* env, ani_object obj, ani_boolean enabled, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnableByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enabled);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributedByBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnableByBundleAndType(ani_env* env, ani_object obj, ani_string deviceType,
    ani_boolean enabled, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnableByBundleAndType called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse slotType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enabled);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledByBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniIsDistributedEnabledBySlot(ani_env* env, ani_enum_item slot, ani_string deviceType,
    ani_object callback)
{
    ANS_LOGD("AniIsDistributedEnabledBySlot called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, slot, asyncCallbackInfo->slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse slotType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_DISTURB_ENABLED_BY_SLOT;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledBySlot(
                        asyncCallbackInfo->slotType, asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnableBySlot(ani_env *env, ani_enum_item slot, ani_string deviceType,
    ani_boolean enable, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnableBySlot called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, slot, asyncCallbackInfo->slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse slotType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledBySlot(
                        asyncCallbackInfo->slotType, asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniIsDistributedEnabledByDeviceType(ani_env* env, ani_string deviceType, ani_object callback)
{
    ANS_LOGD("AniIsDistributedEnabledByDeviceType called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_DISTURB_ENABLED_BY_DEVICE_TYPE;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(
                        asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnabledByDeviceType(ani_env* env,
    ani_boolean enable, ani_string deviceType, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnabledByDeviceType called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabled(
                        asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetDistributedEnableByBundles(ani_env* env, ani_object obj, ani_string deviceType, ani_object callback)
{
    ANS_LOGD("AniSetDistributedEnableByBundles called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayDistributedBundleOption(env, obj, asyncCallbackInfo->bundles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayDistributedBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedBundleOption(
                        asyncCallbackInfo->bundles, asyncCallbackInfo->deviceTypeStr);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniGetDistributedDeviceList(ani_env* env, ani_object callback)
{
    ANS_LOGD("AniGetDistributedDeviceList called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = GET_DISTURB_ENABLED_DEVICE_LIST;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedDevicelist(
                        asyncCallbackInfo->deviceList);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetTargetDeviceStatus(ani_env* env, ani_string deviceType, ani_long deviceStatus, ani_object callback)
{
    ANS_LOGD("AniSetTargetDeviceStatus called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->status = static_cast<int32_t>(deviceStatus);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceStatus(
                        asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->status, DISTURB_DEFAULT_FLAG);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniIsSmartReminderEnabled(ani_env* env, ani_string deviceType, ani_object callback)
{
    ANS_LOGD("AniIsSmartReminderEnabled called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_SMART_REMINDER_ENABLE;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsSmartReminderEnabled(
                        asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}

ani_object AniSetSmartReminderEnable(ani_env* env, ani_string deviceType, ani_boolean enable, ani_object callback)
{
    ANS_LOGD("AniSetSmartReminderEnable called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDistributedInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, deviceType, asyncCallbackInfo->deviceTypeStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse deviceType failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->isEnabled = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetVM failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDistributedInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetSmartReminderEnabled(
                        asyncCallbackInfo->deviceTypeStr, asyncCallbackInfo->isEnabled);
            }
        },
        HandleDistribCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}
}
}
