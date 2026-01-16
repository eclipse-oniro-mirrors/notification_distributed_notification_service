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
#include "ani_cance.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackCancelInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackCancelInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackCancelInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackCancelInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackCancelInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackCancelInfo* asyncCallbackInfo)
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

void HandleCancelCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackCancelInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

ani_object AniCancelAll(ani_env *env, ani_object callback)
{
    ANS_LOGD("AniCancelAll enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
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

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelAllNotifications();
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelWithId(ani_env *env, ani_int id, ani_object callback)
{
    ANS_LOGD("AniCancelWithId enter");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    };
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->notificationId = id;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelNotification(
                    asyncData->notificationId);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelWithIdLabel(ani_env *env, ani_int id, ani_string label, ani_object callback)
{
    ANS_LOGD("AniCancelWithIdLabel called");
    std::string tempStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, label, tempStr)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse label failed!");
        return nullptr;
    }
    std::string labelStr = NotificationSts::GetResizeStr(tempStr, OHOS::NotificationSts::STR_MAX_SIZE);
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->notificationId = id;
    asyncCallbackInfo->labelStr = labelStr;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelNotification(
                    asyncData->labelStr, asyncData->notificationId);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelWithBundle(ani_env *env, ani_object bundleObj, ani_int id, ani_object callback)
{
    ANS_LOGD("AniCancelWithBundle call");
    BundleOption bundleOption;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, bundleOption)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed!");
        return nullptr;
    }

    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->bundleOption = bundleOption;
    asyncCallbackInfo->notificationId = id;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelAsBundleWithAgent(
                    asyncData->bundleOption, asyncData->notificationId);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelAsBundle(ani_env *env, ani_int id, ani_string representativeBundle,
    ani_int userId, ani_object callback)
{
    std::string bundleStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, representativeBundle, bundleStr)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "representativeBundle parse failed!");
        return nullptr;
    }
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->convertedId = id;
    asyncCallbackInfo->userId = userId;
    asyncCallbackInfo->bundleStr = bundleStr;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelAsBundle(
                    asyncData->convertedId, asyncData->bundleStr, asyncData->userId);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle,
    ani_int userId, ani_object callback)
{
    ANS_LOGD("AniCancelAsBundleWithBundleOption called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::UnwrapBundleOption(env, representativeBundle, asyncCallbackInfo->bundleOption) != true) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed!");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->userId = static_cast<int32_t>(userId);
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelAsBundle(
                    asyncData->bundleOption, asyncData->userId);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniCancelGroup(ani_env *env, ani_string groupName, ani_object callback)
{
    ANS_LOGD("AniCancelGroup called");
    std::string tempStr;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, groupName, tempStr)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse groupName failed!");
        return nullptr;
    }
    std::string groupNameStr = NotificationSts::GetResizeStr(tempStr, OHOS::NotificationSts::STR_MAX_SIZE);
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackCancelInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    env->GetVM(&asyncCallbackInfo->vm);
    asyncCallbackInfo->groupNameStr = groupNameStr;
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncData = static_cast<AsyncCallbackCancelInfo*>(data);
            if (asyncData) {
                asyncData->info.returnCode = Notification::NotificationHelper::CancelGroup(
                    asyncData->groupNameStr);
            }
        },
        HandleCancelCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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