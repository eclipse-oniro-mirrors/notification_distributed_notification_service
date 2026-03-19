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
#include "ani_notification_subscriber_extension.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "ani_notification_extension_subscription_info.h"

namespace OHOS {
namespace NotificationExtensionSubScriptionSts {
using namespace arkts::concurrency_helpers;
void DeleteCallBackInfoWithoutPromise(ani_env *env, AsyncCallbackInfoNotificationExtension *asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackInfoNotificationExtension Without Promise");
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

void DeleteCallBackInfo(ani_env *env, AsyncCallbackInfoNotificationExtension *asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackInfoNotificationExtension");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackInfoNotificationExtension *asyncCallbackInfo)
{
    if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, envCurr) != ANI_OK || envCurr == nullptr) {
        ANS_LOGE("GetEnv failed");
        if (asyncCallbackInfo != nullptr) {
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
        }
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

ani_object AniSubscribe(ani_env *env, ani_object notificationInfoArrayobj)
{
    ANS_LOGD("AniSubscribe enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    ani_status statusParam = NotificationSts::UnwarpNotificationExtensionSubscribeInfoArrayByAniObj(
        env, notificationInfoArrayobj, asyncCallbackInfo->subscriptionInfo);
    if (statusParam != ANI_OK) {
        ANS_LOGE("UnwarpNotificationExtensionSubscribeInfoArrayByAniObj failed with %{public}d", statusParam);
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::SUBSCRIBE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::NotificationExtensionSubscribe(
                    asyncCallbackInfo->subscriptionInfo);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniUnsubscribe(ani_env *env)
{
    ANS_LOGD("AniUnsubscribe enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::UNSUBSCRIBE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::NotificationExtensionUnsubscribe();
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetSubscribeInfo(ani_env *env)
{
    ANS_LOGD("AniGetSubscribeInfo enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::GET_SUBSCRIBE_INFO;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::GetSubscribeInfo(asyncCallbackInfo->subscriptionInfo);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetAllSubscriptionBundles(ani_env *env)
{
    ANS_LOGD("AniGetAllSubscriptionBundles enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::GET_ALL_SUBSCRIPTION_BUNDLES;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::GetAllSubscriptionBundles(asyncCallbackInfo->bundles);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsUserGranted(ani_env *env)
{
    ANS_LOGD("AniIsUserGranted enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::IS_USER_GRANTED;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::IsUserGranted(asyncCallbackInfo->enabled);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetUserGrantedState(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniGetUserGrantedState enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->targetBundle) ||
        asyncCallbackInfo->targetBundle.GetBundleName().empty()) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::GET_USER_GRANTED_STATE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetUserGrantedState(
                    asyncCallbackInfo->targetBundle, asyncCallbackInfo->enabled);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetUserGrantedState(ani_env *env, ani_object bundleOption, ani_boolean enable)
{
    ANS_LOGD("AniSetUserGrantedState enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->targetBundle) ||
        asyncCallbackInfo->targetBundle.GetBundleName().empty()) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->enabled = NotificationSts::AniBooleanToBool(enable);

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::SET_USER_GRANTED_STATE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetUserGrantedState(
                    asyncCallbackInfo->targetBundle, asyncCallbackInfo->enabled);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetUserGrantedEnabledBundles(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniGetUserGrantedEnabledBundles enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->targetBundle) ||
        asyncCallbackInfo->targetBundle.GetBundleName().empty()) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::GET_USER_GRANTED_ENABLED_BUNDLES;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetUserGrantedEnabledBundles(
                    asyncCallbackInfo->targetBundle, asyncCallbackInfo->bundles);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetUserGrantedEnabledBundlesForSelf(ani_env *env)
{
    ANS_LOGD("AniGetUserGrantedEnabledBundlesForSelf enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::GET_USER_GRANTED_ENABLED_BUNDLES_FOR_SELF;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::GetUserGrantedEnabledBundlesForSelf(asyncCallbackInfo->bundles);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetUserGrantedBundleState(ani_env *env, ani_object bundleOption, ani_object bundles, ani_boolean enabled)
{
    ANS_LOGD("AniSetUserGrantedBundleState enter");
    auto asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfoNotificationExtension();
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, asyncCallbackInfo->targetBundle) ||
        asyncCallbackInfo->targetBundle.GetBundleName().empty()) {
        ANS_LOGE("UnwrapBundleOption failed");
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    std::vector<BundleOption> bundlesArray;
    if (!NotificationSts::UnwrapArrayBundleOption(env, bundles, bundlesArray) || bundlesArray.empty()) {
        ANS_LOGE("UnwrapArrayBundleOption failed");
        NotificationSts::ThrowErrorWithInvalidParam(env);
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    for (const auto& bundle : bundlesArray) {
        asyncCallbackInfo->bundles.emplace_back(sptr<BundleOption>::MakeSptr(bundle));
    }
    asyncCallbackInfo->enabled = NotificationSts::AniBooleanToBool(enabled);

    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);

    env->GetVM(&asyncCallbackInfo->vm);

    asyncCallbackInfo->funcType = NotificationExtensionFunctionType::SET_USER_GRANTED_BUNDLE_STATE;
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env *env, void *data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetUserGrantedBundleState(
                    asyncCallbackInfo->targetBundle, asyncCallbackInfo->bundles, asyncCallbackInfo->enabled);
            }
        },
        HandleAsyncCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

void HandleAsyncCallbackComplete(ani_env *env, WorkStatus status, void *data)
{
    ANS_LOGD("HandleAsyncCallbackComplete enter");
    auto asyncCallbackInfo = static_cast<AsyncCallbackInfoNotificationExtension*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    HandleAsyncCallbackCompleteInner(envCurr, asyncCallbackInfo);
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

void HandleAsyncCallbackCompleteInner(ani_env *envCurr, AsyncCallbackInfoNotificationExtension *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ANS_LOGD("funcType: %{public}d", asyncCallbackInfo->funcType);
    switch (asyncCallbackInfo->funcType) {
        case NotificationExtensionFunctionType::SUBSCRIBE:
        case NotificationExtensionFunctionType::UNSUBSCRIBE:
        case NotificationExtensionFunctionType::SET_USER_GRANTED_STATE:
        case NotificationExtensionFunctionType::SET_USER_GRANTED_BUNDLE_STATE:
            // void
            break;
        case NotificationExtensionFunctionType::GET_SUBSCRIBE_INFO:
            if (!NotificationSts::WrapNotificationExtensionSubscribeInfoArray(
                envCurr, asyncCallbackInfo->subscriptionInfo, asyncCallbackInfo->info.result)) {
                ANS_LOGE("WrapNotificationExtensionSubscribeInfoArray failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        case NotificationExtensionFunctionType::GET_ALL_SUBSCRIPTION_BUNDLES:
        case NotificationExtensionFunctionType::GET_USER_GRANTED_ENABLED_BUNDLES:
            if (!NotificationSts::GetAniArrayBundleOptionV2(
                envCurr, asyncCallbackInfo->bundles, asyncCallbackInfo->info.result) ||
                asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("GetAniArrayBundleOptionV2 failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        case NotificationExtensionFunctionType::IS_USER_GRANTED:
        case NotificationExtensionFunctionType::GET_USER_GRANTED_STATE:
            asyncCallbackInfo->info.result = NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->enabled);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        case NotificationExtensionFunctionType::GET_USER_GRANTED_ENABLED_BUNDLES_FOR_SELF:
            if (!NotificationSts::SetAniArrayGrantedBundleInfo(
                envCurr, asyncCallbackInfo->bundles, asyncCallbackInfo->info.result) ||
                asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("SetAniArrayGrantedBundleInfo failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            }
            break;
        default:
            ANS_LOGW("unhandled funcType");
            break;
    }
}
} // namespace NotificationExtensionSubScriptionSts
} // namespace OHOS