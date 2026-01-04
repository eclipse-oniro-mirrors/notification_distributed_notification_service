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
#include "ani_get_active.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_request.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackActiveInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackActiveInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackActiveInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackActiveInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackActiveInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackActiveInfo* asyncCallbackInfo) {
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

void GetInfoForGetActiveByFilter(ani_env* envCurr, AsyncCallbackActiveInfo* asyncCallbackInfo)
{
    if (asyncCallbackInfo->notificationRequest == nullptr) {
        asyncCallbackInfo->info.result = NotificationSts::GetNullObject(envCurr);
    } else {
        ani_class requestCls;
        if (!NotificationSts::WarpNotificationRequest(envCurr,
            asyncCallbackInfo->notificationRequest.GetRefPtr(), requestCls, asyncCallbackInfo->info.result)) {
            ANS_LOGE("WarpNotificationRequest failed");
            asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
        }
    }
}

void HandleGetActiveFunctionComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackActiveInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case GET_ACTIVE_NOTIFICATION_COUNT:
            asyncCallbackInfo->info.result = NotificationSts::CreateLong(
                envCurr, asyncCallbackInfo->notificationNums);
            break;
        case GET_ALL_ACTIVE_NOTIFICATIONS: {
            ani_array arrayNotificationObj = NotificationSts::GetAniNotificationRequestArrayByNotifocations(
                envCurr, asyncCallbackInfo->notifications);
            if (arrayNotificationObj == nullptr) {
                ANS_LOGE("arrayNotificationObj is nullptr");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            } else {
                asyncCallbackInfo->info.result = static_cast<ani_object>(arrayNotificationObj);
            }
            break;
        }
        case GET_ACTIVE_NOTIFICATIONS: {
            ani_array arrayRequestObj = NotificationSts::GetAniNotificationRequestArray(envCurr,
                asyncCallbackInfo->requests);
            if (arrayRequestObj == nullptr) {
                ANS_LOGE("arrayRequestObj is nullptr");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            } else {
                asyncCallbackInfo->info.result = static_cast<ani_object>(arrayRequestObj);
            }
            break;
        }
        case GET_ACTIVE_NOTIFICATIONS_BY_FILTER: {
            GetInfoForGetActiveByFilter(envCurr, asyncCallbackInfo);
            break;
        }
        default:
            break;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniGetActiveNotificationCount(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetActiveNotificationCount called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackActiveInfo{.asyncWork = nullptr};
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_ACTIVE_NOTIFICATION_COUNT;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackActiveInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetActiveNotificationNums(
                    asyncCallbackInfo->notificationNums);
            }
        },
        HandleGetActiveFunctionComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetAllActiveNotifications(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetAllActiveNotifications called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackActiveInfo{.asyncWork = nullptr};
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_ALL_ACTIVE_NOTIFICATIONS;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackActiveInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetAllActiveNotifications(
                    asyncCallbackInfo->notifications);
            }
        },
        HandleGetActiveFunctionComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetActiveNotifications(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetActiveNotifications called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackActiveInfo{.asyncWork = nullptr};
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
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->functionType = GET_ACTIVE_NOTIFICATIONS;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackActiveInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetActiveNotifications(
                    asyncCallbackInfo->requests);
            }
        },
        HandleGetActiveFunctionComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

void ExecuteGetActiveNotificationByFilter(ani_env* env, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackActiveInfo*>(data);
    if (asyncCallbackInfo) {
        asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetActiveNotificationByFilter(
            asyncCallbackInfo->liveViewFilter, asyncCallbackInfo->notificationRequest);
        ani_env *envCurr = nullptr;
        if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, &envCurr) != ANI_OK || envCurr == nullptr) {
            ANS_LOGE("GetEnv failed");
            return;
        }
        if (asyncCallbackInfo->info.returnCode != ERR_OK &&
            asyncCallbackInfo->info.returnCode != Notification::ERR_ANS_NOTIFICATION_NOT_EXISTS) {
            ANS_LOGE("AniGetActiveNotificationByFilter error, errorCode: %{public}d",
                asyncCallbackInfo->info.returnCode);
            return;
        }
    }
}

ani_object AniGetActiveNotificationByFilter(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniGetActiveNotificationByFilter called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackActiveInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!OHOS::NotificationSts::UnWarpNotificationFilter(env, obj, asyncCallbackInfo->liveViewFilter)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationFilter failed");
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
    asyncCallbackInfo->functionType = GET_ACTIVE_NOTIFICATIONS_BY_FILTER;
    WorkStatus status = CreateAsyncWork(env, ExecuteGetActiveNotificationByFilter,
        HandleGetActiveFunctionComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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
} // namespace NotificationManagerSts
} // namespace OHOS