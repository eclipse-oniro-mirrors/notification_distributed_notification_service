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
#include "ani_notification_enable.h"

#include "ans_notification.h"
#include "singleton.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
using namespace OHOS::Notification;
using OHOS::Notification::AnsNotification;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackEnabledInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackEnabledInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackEnabledInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackEnabledInfo");
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

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackEnabledInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackEnabledInfo* asyncCallbackInfo)
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

void HandleNotificationEnabledCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case IS_NOTIFICATION_ENABLED:
        case IS_NOTIFICATION_ENABLED_WITH_ID:
        case IS_NOTIFICATION_ENABLED_WITH_BUNDLE_OPTION:
        case GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP: {
            asyncCallbackInfo->info.result =
                OHOS::NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->isAllowed);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isAllowed failed");
                asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
            }
            break;
        }
        case GET_ALL_NOTIFICATION_ENABLED_BUNDLES:
        case GET_ALL_NOTIFICATION_ENABLED_BUNDLES_BY_USER_ID: {
            asyncCallbackInfo->info.result =
                NotificationSts::GetAniArrayBundleOption(envCurr, asyncCallbackInfo->bundleOptions);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("GetAniArrayBundleOption failed");
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

ani_object AniIsNotificationEnabled(ani_env *env, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->functionType = IS_NOTIFICATION_ENABLED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotifySelf(
                        asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_object AniIsNotificationEnabledWithId(ani_env *env, ani_int userId, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->userId = userId;
    asyncCallbackInfo->functionType = IS_NOTIFICATION_ENABLED_WITH_ID;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(
                        asyncCallbackInfo->userId, asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_object AniIsNotificationEnabledWithBundleOption(ani_env *env, ani_object bundleOption, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->notificationOption)) {
        ANS_LOGE("UnwrapBundleOption failed");
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
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->functionType = IS_NOTIFICATION_ENABLED_WITH_BUNDLE_OPTION;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(
                        asyncCallbackInfo->notificationOption, asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_object AniSetNotificationEnable(ani_env *env, ani_object bundleOption, ani_boolean enable, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->notificationOption)) {
        ANS_LOGE("UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->isAllowed = NotificationSts::AniBooleanToBool(enable);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                std::string deviceId {""};
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForSpecifiedBundle(
                        asyncCallbackInfo->notificationOption, deviceId, asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_object AniSetSyncNotificationEnabledWithoutApp(ani_env *env, ani_int userId, ani_boolean enabled,
    ani_object callback)
{
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->userId = userId;
    asyncCallbackInfo->isAllowed = NotificationSts::AniBooleanToBool(enabled);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetSyncNotificationEnabledWithoutApp(
                        asyncCallbackInfo->userId, asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetAllNotificationEnabledBundles(ani_env *env, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->functionType = GET_ALL_NOTIFICATION_ENABLED_BUNDLES;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationEnabledBundles(
                        asyncCallbackInfo->bundleOptions);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_object AniGetAllNotificationEnabledBundlesByUserId(ani_env *env, ani_int userId, ani_object callback)
{
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->userId = userId;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->functionType = GET_ALL_NOTIFICATION_ENABLED_BUNDLES_BY_USER_ID;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationEnabledBundles(
                        asyncCallbackInfo->bundleOptions, asyncCallbackInfo->userId);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}

ani_boolean AniIsNotificationEnabledSync(ani_env *env)
{
    bool allowed = false;
    uint32_t svcCode =
        DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotifySelf(allowed);
    if (svcCode != ERR_ANS_INNER_OK) {
        ANS_LOGE("AniIsNotificationEnabledSync error, errorCode: %{public}u", svcCode);
        OHOS::NotificationSts::ThrowErrorWithCode(env, svcCode);
        return NotificationSts::BoolToAniBoolean(false);
    }
    return NotificationSts::BoolToAniBoolean(allowed);
}

ani_object AniGetSyncNotificationEnabledWithoutApp(ani_env *env, ani_int userId, ani_object callback)
{
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->userId = userId;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->functionType = GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetSyncNotificationEnabledWithoutApp(
                        asyncCallbackInfo->userId, asyncCallbackInfo->isAllowed);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniDisableNotificationFeature(ani_env *env, ani_boolean disabled, ani_object bundleList,
    ani_object callback)
{
#ifdef DISABLE_NOTIFICATION_FEATURE_ENABLE
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    std::vector<std::string> bundles;
    if (!NotificationSts::GetStringArrayByAniObj(env, bundleList, bundles)) {
        ANS_LOGE("Parse bundleList failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->param.SetDisabled(NotificationSts::AniBooleanToBool(disabled));
    asyncCallbackInfo->param.SetBundleList(bundles);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->DisableNotificationFeature(
                        asyncCallbackInfo->param);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniDisableNotificationFeatureWithId(ani_env *env, ani_boolean disabled, ani_object bundleList,
    ani_int userId, ani_object callback)
{
#ifdef DISABLE_NOTIFICATION_FEATURE_ENABLE
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackEnabledInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    std::vector<std::string> bundles;
    if (!NotificationSts::GetStringArrayByAniObj(env, bundleList, bundles)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    asyncCallbackInfo->param.SetDisabled(NotificationSts::AniBooleanToBool(disabled));
    asyncCallbackInfo->param.SetBundleList(bundles);
    asyncCallbackInfo->param.SetUserId(userId);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, callback, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackEnabledInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->DisableNotificationFeature(
                        asyncCallbackInfo->param);
            }
        },
        HandleNotificationEnabledCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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
} // namespace NotificationManagerSts
} // namespace OHOS
