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
#include "ani_do_not_disturb_profile.h"

#include "ans_notification.h"
#include "singleton.h"
#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
using namespace OHOS::Notification;
using OHOS::Notification::AnsNotification;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackProfileInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackProfileInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackProfileInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackProfileInfo");
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

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackProfileInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackProfileInfo* asyncCallbackInfo)
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

void HandleDisturbProfileCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    if (asyncCallbackInfo->functionType == GET_DO_NOT_DISTURB_PROFILE ||
        asyncCallbackInfo->functionType == GET_DO_NOT_DISTURB_PROFILE_BY_USER_ID) {
        if (!NotificationSts::WrapDoNotDisturbProfile(envCurr,
            asyncCallbackInfo->doNotDisturbProfile, asyncCallbackInfo->info.result)) {
            ANS_LOGE("WrapDoNotDisturbProfile failed");
            asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
        }
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniAddDoNotDisturbProfile(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniAddDoNotDisturbProfile called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, asyncCallbackInfo->profiles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayDoNotDisturbProfile failed");
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
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->AddDoNotDisturbProfiles(
                    asyncCallbackInfo->profiles);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniAddDoNotDisturbProfileByUserId(ani_env *env, ani_object obj, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniAddDoNotDisturbProfileByUserId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, asyncCallbackInfo->profiles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayDoNotDisturbProfile failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->userId = userId;
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

    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->AddDoNotDisturbProfiles(
                    asyncCallbackInfo->profiles, asyncCallbackInfo->userId);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniRemoveDoNotDisturbProfile(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniRemoveDoNotDisturbProfile called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, asyncCallbackInfo->profiles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayDoNotDisturbProfile failed");
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

    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->RemoveDoNotDisturbProfiles(
                    asyncCallbackInfo->profiles);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniRemoveDoNotDisturbProfileByUserId(ani_env *env, ani_object obj, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniRemoveDoNotDisturbProfileByUserId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayDoNotDisturbProfile(env, obj, asyncCallbackInfo->profiles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapArrayDoNotDisturbProfile failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->userId = userId;
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

    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->RemoveDoNotDisturbProfiles(
                    asyncCallbackInfo->profiles, asyncCallbackInfo->userId);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetDoNotDisturbProfile(ani_env *env, ani_long id, ani_object callback)
{
    ANS_LOGD("AniGetDoNotDisturbProfile called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    asyncCallbackInfo->doNotDisturbProfile = new (std::nothrow) NotificationDoNotDisturbProfile();
    if (asyncCallbackInfo->doNotDisturbProfile == nullptr) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "doNotDisturbProfile is nullptr");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->notificationId = id;
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
    asyncCallbackInfo->functionType = GET_DO_NOT_DISTURB_PROFILE;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbProfile(
                    asyncCallbackInfo->notificationId, asyncCallbackInfo->doNotDisturbProfile);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetDoNotDisturbProfileByUserId(ani_env *env, ani_long id, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniGetDoNotDisturbProfileByUserId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackProfileInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    asyncCallbackInfo->doNotDisturbProfile = new (std::nothrow) NotificationDoNotDisturbProfile();
    if (asyncCallbackInfo->doNotDisturbProfile == nullptr) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "doNotDisturbProfile is nullptr");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->notificationId = id;
    asyncCallbackInfo->userId = userId;
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
    asyncCallbackInfo->functionType = GET_DO_NOT_DISTURB_PROFILE_BY_USER_ID;
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackProfileInfo*>(data);
            asyncCallbackInfo->info.returnCode =
                DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbProfile(
                    asyncCallbackInfo->notificationId, asyncCallbackInfo->doNotDisturbProfile,
                    asyncCallbackInfo->userId);
        },
        HandleDisturbProfileCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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
}
}
