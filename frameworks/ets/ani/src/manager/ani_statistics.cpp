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
#include "notification_helper.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackStatistics* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackReminderInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackStatistics* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackReminderInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
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
        ANS_LOGE("GetAniArrayReminderInfo failed");
        asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniGetNotificationStatisticsByBundle(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniGetNotificationStatisticsByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackStatistics{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, asyncCallbackInfo->bundles)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackStatistics*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetStatisticsByBundle(
                    asyncCallbackInfo->bundles, asyncCallbackInfo->statisticsInfos);
            }
        },
        HandleStatisticsFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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