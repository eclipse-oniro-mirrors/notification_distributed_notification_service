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
#include "ani_slot.h"

#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_slot.h"
#include "notification_slot.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackSlotInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackSlotInfo Without Promise");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.callback != nullptr) {
        ANS_LOGD("Delete callback reference");
        env->GlobalReference_Delete(asyncCallbackInfo->info.callback);
    }
    if (asyncCallbackInfo->asyncWork != nullptr) {
        ANS_LOGD("DeleteAsyncWork");
        DeleteAsyncWork(env, asyncCallbackInfo->asyncWork);
        asyncCallbackInfo->asyncWork = nullptr;
    }
    if (asyncCallbackInfo->slot) {
        delete asyncCallbackInfo->slot;
        asyncCallbackInfo->slot = nullptr;
    }
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

void DeleteCallBackInfo(ani_env* env, AsyncCallbackSlotInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackSlotInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackSlotInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackSlotInfo* asyncCallbackInfo)
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

void HandleSlotFunctionCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case GET_SLOT_FLAGS_BY_BUNDLE: {
            asyncCallbackInfo->info.result = NotificationSts::CreateLong(envCurr,
                asyncCallbackInfo->slotFlags);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateLong for slotFlags failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        case GET_SLOTS:
        case GET_SLOTS_BY_BUNDLE: {
            ani_array outAniObj;
            if (!NotificationSts::WrapNotificationSlotArray(env, asyncCallbackInfo->slots, outAniObj)) {
                ANS_LOGE("WrapNotificationSlotArray failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            asyncCallbackInfo->info.result = static_cast<ani_object>(outAniObj);
            break;
        }
        case IS_NOTIFICATION_SLOT_ENABLED: {
            asyncCallbackInfo->info.result =
                NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->param.isEnabled);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isEnabled failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        default:
            break;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

void HandleSlotFunctionCallbackComplete1(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case GET_SLOT:
        case GET_SLOT_BY_BUNDLE:{
            if (asyncCallbackInfo->slot == nullptr) {
                ANS_LOGD("slot is null");
                break;
            }
            if (!NotificationSts::WrapNotificationSlot(env,
                asyncCallbackInfo->slot, asyncCallbackInfo->info.result) ||
                asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("WrapNotificationSlot failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        case GET_SLOT_NUM_BY_BUNDLE:{
            asyncCallbackInfo->info.result = NotificationSts::CreateLong(envCurr,
                asyncCallbackInfo->slotNum);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateLong for slotNum failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        case GET_NOTIFICATION_SETTING:{
            if (!NotificationSts::WrapGetNotificationSetting(env,
                asyncCallbackInfo->slotFlags, asyncCallbackInfo->info.result) ||
                asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("WrapGetNotificationSetting failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        default:
            break;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

bool UnwrapEnableSlotParameter(ani_env* env, ani_object parameterObj, AsyncCallbackSlotInfo* asyncCallbackInfo)
{
    ANS_LOGD("UnwrapEnableSlotParameter called");
    ani_ref bundleOption;
    if (env->Object_GetPropertyByName_Ref(parameterObj, "bundle", &bundleOption) != ANI_OK) {
        ANS_LOGE("Parse enable failed");
        return false;
    }
    if (!(NotificationSts::UnwrapBundleOption(env,
        static_cast<ani_object>(bundleOption), asyncCallbackInfo->param.option))) {
        ANS_LOGE("UnwrapBundleOption failed");
        return false;
    }
    ani_ref type;
    if (env->Object_GetPropertyByName_Ref(parameterObj, "type", &type) != ANI_OK) {
        ANS_LOGE("Parse enable failed");
        return false;
    }
    if (!(NotificationSts::SlotTypeEtsToC(env,
        static_cast<ani_enum_item>(type), asyncCallbackInfo->param.slotType))) {
        ANS_LOGE("SlotTypeEtsToC failed");
        return false;
    }
    ani_boolean enable = ANI_FALSE;
    if (env->Object_GetPropertyByName_Boolean(parameterObj, "enable", &enable) != ANI_OK) {
        ANS_LOGE("Parse enable failed");
        return false;
    }
    asyncCallbackInfo->param.isEnabled = NotificationSts::AniBooleanToBool(enable);
    ani_boolean isForceControl = ANI_FALSE;
    if (env->Object_GetPropertyByName_Boolean(parameterObj, "isForceControl", &isForceControl) != ANI_OK) {
        ANS_LOGE("Parse isForceControl failed");
        return false;
    }
    asyncCallbackInfo->param.isForceControl = NotificationSts::AniBooleanToBool(isForceControl);
    return true;
}

ani_object AniGetSlotsByBundle(ani_env *env, ani_object bundleOption, ani_object callback)
{
    ANS_LOGD("AniGetSlotsByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->param.option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOptionfailed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOTS_BY_BUNDLE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlotsForBundle(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->slots);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniAddSlots(ani_env *env, ani_object notificationSlotArrayObj, ani_object callback)
{
    ANS_LOGD("AniAddSlots called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapNotificationSlotArrayByAniObj(env,
        notificationSlotArrayObj, asyncCallbackInfo->param.slots)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapNotificationSlotArrayByAniObj failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::AddNotificationSlots(
                    asyncCallbackInfo->param.slots);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniAddSlotByNotificationSlot(ani_env *env, ani_object notificationSlotObj, ani_object callback)
{
    ANS_LOGD("AniAddSlotByNotificationSlot called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapNotificationSlot(env, notificationSlotObj, asyncCallbackInfo->param.slot)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapNotificationSlot failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::AddNotificationSlot(
                    asyncCallbackInfo->param.slot);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniAddSlotBySlotType(ani_env *env, ani_enum_item enumObj, ani_object callback)
{
    ANS_LOGD("AniAddSlotBySlotType enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "SlotTypeEtsToC failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::AddSlotByType(
                    asyncCallbackInfo->param.slotType);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSlot(ani_env *env, ani_enum_item enumObj, ani_object callback)
{
    ANS_LOGD("AniGetSlot called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "SlotTypeEtsToC failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOT;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlot(
                    asyncCallbackInfo->param.slotType, asyncCallbackInfo->slot);
            }
        },
        HandleSlotFunctionCallbackComplete1, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSlots(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetSlots enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOTS;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlots(
                    asyncCallbackInfo->slots);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniRemoveSlot(ani_env *env, ani_enum_item enumObj, ani_object callback)
{
    ANS_LOGD("AniRemoveSlot called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, enumObj, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "SlotTypeEtsToC failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::RemoveNotificationSlot(
                    asyncCallbackInfo->param.slotType);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniRemoveAllSlots(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniRemoveAllSlots called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::RemoveAllSlots();
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetSlotByBundle(ani_env *env, ani_object bundleOptionObj, ani_object slotObj, ani_object callback)
{
    ANS_LOGD("AniSetSlotByBundle enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }

    if ((!NotificationSts::UnwrapBundleOption(env, bundleOptionObj, asyncCallbackInfo->param.option)) ||
        (!NotificationSts::UnwrapNotificationSlot(env, slotObj, asyncCallbackInfo->param.slot))) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "AniSetSlotByBundle Unwrap param failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    asyncCallbackInfo->slot = new (std::nothrow) Notification::NotificationSlot(asyncCallbackInfo->param.slot);
    if (asyncCallbackInfo->slot == nullptr) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo->slot is nullptr");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->slots.emplace_back(asyncCallbackInfo->slot);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::UpdateNotificationSlots(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->slots);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSlotNumByBundle(ani_env *env, ani_object bundleOption, ani_object callback)
{
    ANS_LOGD("AniGetSlotNumByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->param.option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOT_NUM_BY_BUNDLE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlotNumAsBundle(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->slotNum);
            }
        },
        HandleSlotFunctionCallbackComplete1, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetNotificationEnableSlot(ani_env *env, ani_object bundleOption, ani_enum_item  type,
    ani_boolean enable, ani_object callback)
{
    ANS_LOGD("AniSetNotificationEnableSlot enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->param.option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!NotificationSts::SlotTypeEtsToC(env, type, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "AniSetNotificationEnableSlot ERROR_INTERNAL_ERROR");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->param.isEnabled = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetEnabledForBundleSlot(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->param.slotType,
                    asyncCallbackInfo->param.isEnabled, asyncCallbackInfo->param.isForceControl);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetNotificationEnableSlotWithForce(ani_env *env, ani_object parameterObj, ani_object callback)
{
    ANS_LOGD("AniSetNotificationEnableSlotWithForce enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!UnwrapEnableSlotParameter(env, parameterObj, asyncCallbackInfo)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapEnableSlotParameter failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetEnabledForBundleSlot(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->param.slotType,
                    asyncCallbackInfo->param.isEnabled, asyncCallbackInfo->param.isForceControl);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsNotificationSlotEnabled(ani_env *env, ani_object bundleOption, ani_enum_item type, ani_object callback)
{
    ANS_LOGD("AniIsNotificationSlotEnabled enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->param.option)
        || !NotificationSts::SlotTypeEtsToC(env, type, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "IsNotificationSlotEnabled : Parse parameter failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = IS_NOTIFICATION_SLOT_ENABLED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetEnabledForBundleSlot(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->param.slotType,
                    asyncCallbackInfo->param.isEnabled);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniGetSlotFlagsByBundle enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->param.option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOT_FLAGS_BY_BUNDLE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlotFlagsAsBundle(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->slotFlags);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetSlotFlagsByBundle(ani_env *env, ani_object obj, ani_long slotFlags, ani_object callback)
{
    ANS_LOGD("AniSetSlotFlagsByBundle enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->param.option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->slotFlags = static_cast<uint32_t>(slotFlags);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetNotificationSlotFlagsAsBundle(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->slotFlags);
            }
        },
        HandleSlotFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSlotByBundle(ani_env *env, ani_object bundleOption, ani_enum_item type, ani_object callback)
{
    ANS_LOGD("AniGetSlotByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->param.option)
        || !NotificationSts::SlotTypeEtsToC(env, type, asyncCallbackInfo->param.slotType)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "AniGetSlotByBundle : Parse parameter failed");
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_SLOT_BY_BUNDLE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSlotForBundle(
                    asyncCallbackInfo->param.option, asyncCallbackInfo->param.slotType, asyncCallbackInfo->slot);
            }
        },
        HandleSlotFunctionCallbackComplete1, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetNotificationSetting(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetNotificationSetting enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackSlotInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_NOTIFICATION_SETTING;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackSlotInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSettings(
                    asyncCallbackInfo->slotFlags);
            }
        },
        HandleSlotFunctionCallbackComplete1, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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