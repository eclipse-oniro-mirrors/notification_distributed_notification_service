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
#include "ani_do_not_disturb_date.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_request.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackDisturbInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackDisturbInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackDisturbInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackDisturbInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackDisturbInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackDisturbInfo* asyncCallbackInfo) {
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

void HandleDoDisturbDataCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case IS_SUPPORT_DO_NOT_DISTURB_DATE_MODE: {
            asyncCallbackInfo->info.result =
                NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->isSupportDoNotDisturbMode);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isSupportDoNotDisturbMode failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        }
        case GET_DO_NOT_DISTURB_DATE:
        case GET_DO_NOT_DISTURB_DATE_WITH_ID: {
            auto datePtr = std::make_shared<OHOS::Notification::NotificationDoNotDisturbDate>(
                asyncCallbackInfo->doNotDisturbDate);
            if (!OHOS::NotificationSts::WarpNotificationDoNotDisturbDate(envCurr,
                datePtr, asyncCallbackInfo->info.result)) {
                ANS_LOGE("WarpNotificationDoNotDisturbDate failed");
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

ani_object AniSetDoNotDisturbDate(ani_env *env, ani_object date, ani_object callback)
{
    ANS_LOGD("AniSetDoNotDisturbDate called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDisturbInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnWarpNotificationDoNotDisturbDate(env, date, asyncCallbackInfo->doNotDisturbDate)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationDoNotDisturbDate failed");
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetDoNotDisturbDate(
                    asyncCallbackInfo->doNotDisturbDate);
            }
        },
        HandleDoDisturbDataCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetDoNotDisturbDateWithId(ani_env *env, ani_object date, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniSetDoNotDisturbDateWithId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDisturbInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!NotificationSts::UnWarpNotificationDoNotDisturbDate(env, date, asyncCallbackInfo->doNotDisturbDate)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationDoNotDisturbDate failed");
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetDoNotDisturbDate(
                    asyncCallbackInfo->userId, asyncCallbackInfo->doNotDisturbDate);
            }
        },
        HandleDoDisturbDataCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetDoNotDisturbDate(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniGetDoNotDisturbDate called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDisturbInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
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
    asyncCallbackInfo->functionType = GET_DO_NOT_DISTURB_DATE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetDoNotDisturbDate(
                    asyncCallbackInfo->doNotDisturbDate);
            }
        },
        HandleDoDisturbDataCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetDoNotDisturbDateWithId(ani_env *env, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniGetDoNotDisturbDateWithId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDisturbInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->userId = userId;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    asyncCallbackInfo->functionType = GET_DO_NOT_DISTURB_DATE_WITH_ID;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetDoNotDisturbDate(
                    asyncCallbackInfo->userId, asyncCallbackInfo->doNotDisturbDate);
            }
        },
        HandleDoDisturbDataCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsSupportDoNotDisturbMode(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniIsSupportDoNotDisturbMode called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackDisturbInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
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
    asyncCallbackInfo->functionType = IS_SUPPORT_DO_NOT_DISTURB_DATE_MODE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackDisturbInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::DoesSupportDoNotDisturbMode(
                    asyncCallbackInfo->isSupportDoNotDisturbMode);
            }
        },
        HandleDoDisturbDataCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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