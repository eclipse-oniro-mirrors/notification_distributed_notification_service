/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ani_notification_switch.h"

#include "ans_log_wrapper.h"
#include "notification_helper.h"
#include "sts_common.h"
#include "sts_notification_manager.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;

namespace {
void DeleteCallBackInfoWithoutPromise(ani_env *env,
    AsyncCallbackNotificationSwitchInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    if (asyncCallbackInfo->info.callback != nullptr) {
        ani_status status = env->GlobalReference_Delete(asyncCallbackInfo->info.callback);
        if (status != ANI_OK) {
            ANS_LOGW("GlobalReference_Delete callback failed, status: %{public}d", status);
        }
    }
    if (asyncCallbackInfo->asyncWork != nullptr) {
        DeleteAsyncWork(env, asyncCallbackInfo->asyncWork);
        asyncCallbackInfo->asyncWork = nullptr;
    }
    delete asyncCallbackInfo;
}

void DeleteCallBackInfo(ani_env *env, AsyncCallbackNotificationSwitchInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ani_status status = env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
        if (status != ANI_OK) {
            ANS_LOGW("GlobalReference_Delete resolver failed, status: %{public}d", status);
        }
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env *env, ani_object callback,
    AsyncCallbackNotificationSwitchInfo *asyncCallbackInfo)
{
    if (!NotificationSts::IsUndefine(env, callback)) {
        ani_ref globalRef = nullptr;
        if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &globalRef) != ANI_OK) {
            ANS_LOGE("create callback ref failed");
            return false;
        }
        asyncCallbackInfo->info.callback = globalRef;
    }
    return true;
}

bool CheckCompleteEnvironment(ani_env **envCurr,
    AsyncCallbackNotificationSwitchInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, envCurr) != ANI_OK || envCurr == nullptr) {
        ANS_LOGE("GetEnv failed");
        return false;
    }
    if (asyncCallbackInfo->info.returnCode != ERR_OK &&
        asyncCallbackInfo->info.returnCode != Notification::ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED) {
        NotificationSts::CreateReturnData(*envCurr, asyncCallbackInfo->info);
        DeleteCallBackInfoWithoutPromise(*envCurr, asyncCallbackInfo);
        return false;
    }
    return true;
}

ani_object CreateResultOrCallbackReturn(ani_env *env,
    AsyncCallbackNotificationSwitchInfo *asyncCallbackInfo, ani_object promise)
{
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
}
} // namespace

void HandleNotificationSwitchCallbackComplete(ani_env *env, WorkStatus status, void *data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackNotificationSwitchInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }

    if (asyncCallbackInfo->info.returnCode == Notification::ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED) {
        int32_t errorCode = Notification::ERROR_INTERNAL_ERROR;
        std::string errMsg = "Internal error. Database operation failed.";
        ani_object errorObj = NotificationSts::CreateError(envCurr, errorCode, errMsg);
        envCurr->PromiseResolver_Reject(asyncCallbackInfo->info.resolve, static_cast<ani_error>(errorObj));
        DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
        return;
    }

    if (asyncCallbackInfo->functionType == GET_NOTIFICATION_SWITCH) {
        ani_enum_item switchStateItem = nullptr;
        auto switchState = static_cast<Notification::NotificationConstant::SWITCH_STATE>(
            asyncCallbackInfo->enableStatus);
        if (!NotificationSts::SwitchStateCToEts(envCurr, switchState, switchStateItem)) {
            ANS_LOGE("SwitchStateCToEts failed");
            asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
        } else {
            asyncCallbackInfo->info.result = static_cast<ani_object>(switchStateItem);
        }
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniSetNotificationSwitch(ani_env *env, ani_string switchName, ani_boolean switchState,
    ani_int userId)
{
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackNotificationSwitchInfo {
        .asyncWork = nullptr,
    };
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_NO_MEMORY);
    }
    if (NotificationSts::GetStringByAniString(env, switchName, asyncCallbackInfo->switchName) != ANI_OK) {
        ANS_LOGE("GetStringByAniString failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_PARAM_INVALID);
    }
    asyncCallbackInfo->switchState = NotificationSts::AniBooleanToBool(switchState);
    asyncCallbackInfo->userId = userId;

    ani_object promise = nullptr;
    NotificationSts::PaddingCallbackPromiseInfo(
        env, asyncCallbackInfo->info.callback, asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_INTERNAL_ERROR);
    }
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackNotificationSwitchInfo *>(data);
            if (asyncCallbackInfo != nullptr) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetNotificationSwitch(
                    asyncCallbackInfo->switchName, asyncCallbackInfo->switchState, asyncCallbackInfo->userId);
            }
        },
        HandleNotificationSwitchCallbackComplete,
        static_cast<void *>(asyncCallbackInfo), &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || QueueAsyncWork(env, asyncCallbackInfo->asyncWork) != WorkStatus::OK) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_INTERNAL_ERROR);
    }
    return promise;
}

ani_object AniGetNotificationSwitch(ani_env *env, ani_string switchName, ani_int userId)
{
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackNotificationSwitchInfo {
        .asyncWork = nullptr,
    };
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_NO_MEMORY);
    }
    if (NotificationSts::GetStringByAniString(env, switchName, asyncCallbackInfo->switchName) != ANI_OK) {
        ANS_LOGE("GetStringByAniString failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_PARAM_INVALID);
    }
    asyncCallbackInfo->userId = userId;
    asyncCallbackInfo->functionType = GET_NOTIFICATION_SWITCH;

    ani_object promise = nullptr;
    NotificationSts::PaddingCallbackPromiseInfo(
        env, asyncCallbackInfo->info.callback, asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_INTERNAL_ERROR);
    }
    WorkStatus workStatus = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackNotificationSwitchInfo *>(data);
            if (asyncCallbackInfo != nullptr) {
                Notification::NotificationConstant::SWITCH_STATE switchState =
                    Notification::NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetNotificationSwitch(
                    asyncCallbackInfo->switchName, asyncCallbackInfo->userId, switchState);
                asyncCallbackInfo->enableStatus = static_cast<int32_t>(switchState);
            }
        },
        HandleNotificationSwitchCallbackComplete,
        static_cast<void *>(asyncCallbackInfo), &(asyncCallbackInfo->asyncWork));
    if (workStatus != WorkStatus::OK || QueueAsyncWork(env, asyncCallbackInfo->asyncWork) != WorkStatus::OK) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, Notification::ERROR_INTERNAL_ERROR);
    }
    return promise;
}
} // namespace NotificationManagerSts
} // namespace OHOS