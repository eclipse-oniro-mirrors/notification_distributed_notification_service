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
#include "notification_helper.h"
#include "sts_badge_query_callback.h"
#include "sts_callback_promise.h"
#include "sts_common.h"
#include "sts_convert_other.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackBadgeInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackBadgeInfo Without Promise");
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
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackBadgeInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackBadgeInfo* asyncCallbackInfo) {
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

bool WrapBadges(ani_env *env, ani_object &outAniObj,
    const std::map<sptr<Notification::NotificationBundleOption>, bool> &bundleEnable)
{
    ANS_LOGD("WrapBadges enter");
    outAniObj = nullptr;
    outAniObj = NotificationSts::CreateMapObject(env, "std.core.Map", ":");
    if (outAniObj == nullptr) {
        return false;
    }
    ani_ref mapRef = nullptr;
    ani_status status = ANI_ERROR;
    for (const auto& [k, v] : bundleEnable) {
        ani_object bundleObj;
        if (!NotificationSts::WrapBundleOption(env, k, bundleObj) || bundleObj == nullptr) {
            ANS_LOGE("WrapNotificationBadgeInfo: WrapBundleOption failed");
            continue;
        }
        ani_object enable = NotificationSts::CreateBoolean(env, v);
        status = env->Object_CallMethodByName_Ref(outAniObj, "set",
            "YY:C{std.core.Map}", &mapRef,
            static_cast<ani_object>(bundleObj), static_cast<ani_object>(enable));
        if (status != ANI_OK) {
            ANS_LOGE("Faild to set bundleEnable map, status : %{public}d", status);
            continue;
        }
    }
    if (outAniObj == nullptr) {
        return false;
    }
    ANS_LOGD("WrapBadges end");
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
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        case GET_BADGE_NUMBER:
            asyncCallbackInfo->info.result =
                NotificationSts::CreateLong(envCurr, static_cast<ani_long>(asyncCallbackInfo->badgeNumber));
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateLong for badgeNumber failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        case GET_BADGE_DISPLAY_STATUS_BY_BUNDLES: {
            if (!WrapBadges(envCurr, asyncCallbackInfo->info.result, asyncCallbackInfo->bundleEnable)) {
                ANS_LOGE("WrapBadges failed");
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

ani_object AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable, ani_object callback)
{
    ANS_LOGD("AniDisplayBadge called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    } 
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->isEnable = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetShowBadgeEnabledForBundle(
                    asyncCallbackInfo->option, asyncCallbackInfo->isEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsBadgeDisplayed(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniIsBadgeDisplayed call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = IS_BADGE_DISPLAYED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetShowBadgeEnabledForBundle(
                    asyncCallbackInfo->option, asyncCallbackInfo->isEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetBadgeNumber(ani_env *env, ani_int badgeNumber, ani_object callback)
{
    ANS_LOGD("AniSetBadgeNumber call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->badgeNumber = badgeNumber;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetBadgeNumber(
                    asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_int badgeNumber, ani_object callback)
{
    ANS_LOGD("AniSetBadgeNumberByBundle call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->badgeNumber = badgeNumber;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetBadgeNumberByBundle(
                    asyncCallbackInfo->option, asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_status GetBadgesFromAni(ani_env *env, ani_object obj,
    std::vector<std::pair<Notification::NotificationBundleOption, bool>> &badges)
{
    ANS_LOGD("GetBadgesFromAni call");
    ani_boolean isUndefined;
    ani_status status = ANI_ERROR;

    status = env->Reference_IsUndefined(obj, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGE("Failed to check undefined, status: %{public}d", status);
        return ANI_ERROR;
    }
    if (isUndefined == ANI_TRUE) {
        return ANI_ERROR;
    }

    ani_class mapClass;
    if (env->FindClass("std.core.Map", &mapClass) != ANI_OK) {
        ANS_LOGE("Find Map class failed.");
        return ANI_ERROR;
    }
    ani_type typeMap = mapClass;
    ani_boolean isMap;
    status = env->Object_InstanceOf(obj, typeMap, &isMap);
    if (isMap != ANI_TRUE) {
        ANS_LOGE("Current obj is not map type.");
        return ANI_ERROR;
    }

    if (NotificationSts::GetMapByAniMap(env, obj, badges) != ANI_OK) {
        return ANI_ERROR;
    }
    return ANI_OK;
}

ani_object AniSetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniSetBadgeDisplayStatusByBundles call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (GetBadgesFromAni(env, obj, asyncCallbackInfo->options) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "GetBadgesFromAni faild");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetShowBadgeEnabledForBundles(
                    asyncCallbackInfo->options);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniGetBadgeDisplayStatusByBundles call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, asyncCallbackInfo->bundles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayBundleOption faild");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = GET_BADGE_DISPLAY_STATUS_BY_BUNDLES;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetShowBadgeEnabledForBundles(
                    asyncCallbackInfo->bundles, asyncCallbackInfo->bundleEnable);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetBadgeNumber(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetBadgeNumber call");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackBadgeInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = GET_BADGE_NUMBER;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackBadgeInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetBadgeNumber(
                    asyncCallbackInfo->badgeNumber);
            }
        },
        HandleBadgeCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn)
{
    ANS_LOGD("AniOnBadgeNumberQuery called");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOnBadgeNumberQuery(env, fn);
}

void AniOffBadgeNumberQuery(ani_env *env)
{
    ANS_LOGD("AniOffBadgeNumberQuery called");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOffBadgeNumberQuery(env);
}

void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num)
{
    ANS_LOGD("AniHandleBadgeNumberPromise called");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniHandleBadgeNumberPromise(env, bundle, num);
}
}
}
