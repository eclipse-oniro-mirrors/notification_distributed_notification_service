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
#include "ani_publish.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_bundle_option.h"
#include "sts_throw_erro.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackPublishInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackPublishInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackPublishInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackPublishInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackPublishInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackPublishInfo* asyncCallbackInfo)
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

void HandlePublishFunctionCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackPublishInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfo(envCurr, asyncCallbackInfo);
}

void ExecutePublishWork(ani_env* env, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackPublishInfo*>(data);
    if (asyncCallbackInfo) {
        asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::PublishNotification(
            *(asyncCallbackInfo->notificationRequest));
    }
}

ani_object AniPublish(ani_env *env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniPublish called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPublishInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    int32_t ret = NotificationSts::UnWarpNotificationRequest(env, obj, asyncCallbackInfo->notificationRequest);
    if (ret != ERR_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationRequest failed");
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

    WorkStatus status = CreateAsyncWork(env, ExecutePublishWork,
        HandlePublishFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniPublishWithId(ani_env *env, ani_object obj, ani_int userId, ani_object callback)
{
    ANS_LOGD("AniPublishWithId called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPublishInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    int32_t ret = NotificationSts::UnWarpNotificationRequest(env, obj, asyncCallbackInfo->notificationRequest);
    if (ret != ERR_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationRequest failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->notificationRequest->SetOwnerUserId(userId);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env, ExecutePublishWork,
        HandlePublishFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniPublishAsBundle(ani_env *env, ani_object request, ani_string representativeBundle,
    ani_int userId, ani_object callback)
{
    ANS_LOGD("AniPublishAsBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPublishInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    int32_t ret = NotificationSts::UnWarpNotificationRequest(env, request, asyncCallbackInfo->notificationRequest);
    if (ret != ERR_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationRequest failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    std::string bundleStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, representativeBundle, bundleStr)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse representativeBundle failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->notificationRequest->SetOwnerUserId(userId);
    asyncCallbackInfo->notificationRequest->SetOwnerBundleName(bundleStr);
    asyncCallbackInfo->notificationRequest->SetIsAgentNotification(true);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env, ExecutePublishWork,
        HandlePublishFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniPublishAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle,
    ani_object request, ani_object callback)
{
    ANS_LOGD("AniPublishAsBundleWithBundleOption called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPublishInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    int32_t ret = NotificationSts::UnWarpNotificationRequest(env, request, asyncCallbackInfo->notificationRequest);
    if (ret != ERR_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnWarpNotificationRequest failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    BundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, representativeBundle, option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->notificationRequest->SetOwnerBundleName(option.GetBundleName());
    asyncCallbackInfo->notificationRequest->SetOwnerUid(option.GetUid());
    asyncCallbackInfo->notificationRequest->SetIsAgentNotification(true);

    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env, ExecutePublishWork,
        HandlePublishFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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