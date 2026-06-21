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
#include "ani_display_badge.h"

#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "singleton.h"
#include "sts_badge_query_callback.h"
#include "sts_callback_promise.h"
#include "sts_common.h"
#include "sts_convert_other.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
using namespace OHOS::Notification;
using OHOS::Notification::AnsNotification;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackBadgeInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackBadgeInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackBadgeInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackBadgeInfo");
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

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackBadgeInfo* asyncCallbackInfo)
{
    if (!NotificationSts::IsUndefine(env, callback)) {
        ani_ref globalRef;
        if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &globalRef) != ANI_OK) {
            return false;
        }
        asyncCallbackInfo->info.callback = globalRef;
    }
    return true;
}

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackBadgeInfo* asyncCallbackInfo)
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

void HandleBadgeCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case IS_BADGE_DISPLAYED:
            asyncCallbackInfo->info.result =
                NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->isEnable);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isEnable failed");
                asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
            }
            break;
        case GET_BADGE_NUMBER:
            asyncCallbackInfo->info.result =
                NotificationSts::CreateLong(envCurr, static_cast<ani_long>(asyncCallbackInfo->badgeNumber));
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateLong for badgeNumber failed");
                asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
            }
            break;
        case GET_BADGE_DISPLAY_STATUS_BY_BUNDLES: {
            if (!NotificationSts::WrapBundleOptionMap(envCurr,
                asyncCallbackInfo->info.result, asyncCallbackInfo->bundleEnable)) {
                ANS_LOGE("WrapBundleOptionMap failed");
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

ani_object AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->isEnable = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetShowBadgeEnabledForBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->isEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniIsBadgeDisplayed(ani_env *env, ani_object obj, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = IS_BADGE_DISPLAYED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabledForBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->isEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniSetBadgeNumber(ani_env *env, ani_int badgeNumber, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status vmStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (vmStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", vmStatus);
        delete asyncCallbackInfo;
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->badgeNumber = badgeNumber;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumber(
                        asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_int badgeNumber, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->badgeNumber = badgeNumber;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumberByBundle(
                        asyncCallbackInfo->option, asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniSetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (NotificationSts::UnwrapBundleOptionMap(env, obj, asyncCallbackInfo->options) != ANI_OK) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetShowBadgeEnabledForBundles(
                        asyncCallbackInfo->options);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniGetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, asyncCallbackInfo->bundles)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = GET_BADGE_DISPLAY_STATUS_BY_BUNDLES;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabledForBundles(
                        asyncCallbackInfo->bundles, asyncCallbackInfo->bundleEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

ani_object AniGetBadgeNumber(ani_env *env, ani_object callback)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_status status = env->GetVM(&asyncCallbackInfo->vm);
    if (status != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", status);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = GET_BADGE_NUMBER;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetBadgeNumber(
                        asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOnBadgeNumberQuery(env, fn);
#else
    NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

void AniOffBadgeNumberQuery(ani_env *env)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOffBadgeNumberQuery(env);
#else
    NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}

void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num)
{
#ifdef ANS_FEATURE_BADGE_MANAGER
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniHandleBadgeNumberPromise(env, bundle, num);
#endif
}
}
}

