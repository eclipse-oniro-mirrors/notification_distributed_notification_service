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
#include "ani_statistics.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"
#include "sts_notification_statistics.h"
#include "ans_notification.h"
#include "singleton.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
using namespace OHOS::Notification;
using OHOS::Notification::AnsNotification;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackStatistics* asyncCallbackInfo)
{
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackStatistics* asyncCallbackInfo)
{
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackStatistics* asyncCallbackInfo)
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

void HandleStatisticsFunctionCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackStatistics*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    asyncCallbackInfo->info.result =
        NotificationSts::GetAniArrayStatisticsInfo(envCurr, asyncCallbackInfo->statisticsInfos);
    if (asyncCallbackInfo->info.result == nullptr) {
        ANS_LOGE("GetAniArrayStatisticsInfo failed");
        asyncCallbackInfo->info.returnCode = ERR_ANS_INNER_TASK_ERR;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniGetNotificationStatisticsByBundle(ani_env *env, ani_object obj)
{
#ifdef ANS_FEATURE_NOTIFICATION_STATISTICS
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackStatistics{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        return NotificationSts::AniJumpCbError(env, nullptr, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, asyncCallbackInfo->bundles)) {
        ANS_LOGE("UnwrapArrayBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    ani_status aniStatus = env->GetVM(&asyncCallbackInfo->vm);
    if (aniStatus != ANI_OK) {
        ANS_LOGE("GetVM failed, status: %{public}d", aniStatus);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackStatistics*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetStatisticsByBundle(
                        asyncCallbackInfo->bundles, asyncCallbackInfo->statisticsInfos);
            }
        },
        HandleStatisticsFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        ANS_LOGE("CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return NotificationSts::AniJumpCbError(env, nullptr, OHOS::Notification::ERR_ANS_INNER_TASK_ERR);
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return NotificationSts::GetNullObject(env);
#else
    return NotificationSts::AniJumpCbError(env, nullptr, OHOS::Notification::ERR_ANS_INNER_DEVICE_NOT_SUPPORT);
#endif
}
}
}
