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
#include "ani_get_notification_parameters.h"

#include "ans_log_wrapper.h"
#include "notification_helper.h"
#include "sts_request.h"
#include "sts_throw_erro.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;

void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackInfoNotificationParameters* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackInfoNotificationParameters Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackInfoNotificationParameters* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackInfoNotificationParameters");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackInfoNotificationParameters* asyncCallbackInfo)
{
    if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, envCurr) != ANI_OK || envCurr == nullptr || *envCurr == nullptr) {
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

void HandleGetNotificationParametersComplete(ani_env* env, WorkStatus status, void* data)
{
    ANS_LOGD("called");
    auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationParameters*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is null");
        return;
    }

    ani_env* envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }

    if (!NotificationSts::WrapNotificationParameters(envCurr, asyncCallbackInfo->parameters,
        asyncCallbackInfo->info.result)) {
        ANS_LOGE("Create NotificationParameters failed");
        asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniGetNotificationParameters(ani_env *env, ani_int id, ani_string label)
{
    ANS_LOGD("called");
    int32_t notificationId = static_cast<int32_t>(id);

    std::string labelStr = "";
    if (NotificationSts::GetStringByAniString(env, label, labelStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "label parse failed");
        return nullptr;
    }

    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationParameters {
        .asyncWork = nullptr,
        .notificationId = notificationId,
        .label = labelStr
    };
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Failed to create callback info");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->info.isCallback = false;

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackInfoNotificationParameters*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::GetNotificationParameters(
                    asyncData->notificationId, asyncData->label, asyncData->parameters);
            }
        },
        HandleGetNotificationParametersComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Create Async Work or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    return promise;
}

}  // namespace NotificationManagerSts
}  // namespace OHOS