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

#include "ani_priority.h"

#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
constexpr int32_t MAX_TEXT_SIZE = 3072;
void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackPriorityInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackPriorityInfo Without Promise");
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

void DeleteCallBackInfo(ani_env* env, AsyncCallbackPriorityInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackPriorityInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackPriorityInfo* asyncCallbackInfo)
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

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackPriorityInfo* asyncCallbackInfo)
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

void HandlePriorityFunctionCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    switch (asyncCallbackInfo->functionType) {
        case GET_BUNDLE_PRIORITY_CONFIG: {
            ani_string outAniStr;
            if (NotificationSts::GetAniStringByString(envCurr, asyncCallbackInfo->valueStr, outAniStr) != ANI_OK) {
                ANS_LOGE("GetAniStringByString for valueStr failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            } else {
                asyncCallbackInfo->info.result = static_cast<ani_object>(outAniStr);
            }
            break;
        }
        case IS_PRIORITY_ENABLED_BY_BUNDLE: {
            ani_enum_item statusItem {};
            if (!NotificationSts::EnumConvertNativeToAni(envCurr,
                "@ohos.notificationManager.notificationManager.PriorityEnableStatus",
                asyncCallbackInfo->status, statusItem)) {
                ANS_LOGE("Convert PriorityEnableStatus to ani failed");
                asyncCallbackInfo->info.returnCode = Notification::ERROR_INTERNAL_ERROR;
            } else {
                asyncCallbackInfo->info.result = static_cast<ani_object>(statusItem);
            }
            break;
        }
        case IS_PRIORITY_ENABLED: {
            asyncCallbackInfo->info.result =
                NotificationSts::CreateBoolean(envCurr, asyncCallbackInfo->isPriorityEnabled);
            if (asyncCallbackInfo->info.result == nullptr) {
                ANS_LOGE("CreateBoolean for isPriorityEnabled failed");
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

ani_object AniSetBundlePriorityConfig(ani_env* env, ani_object obj, ani_string value, ani_object callback)
{
    ANS_LOGD("AniSetBundlePriorityConfig called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (NotificationSts::GetStringByAniString(env, value, asyncCallbackInfo->valueStr) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse valueStr failed.");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->valueStr = NotificationSts::GetResizeStr(asyncCallbackInfo->valueStr, MAX_TEXT_SIZE);
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed.");
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
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetBundlePriorityConfig(
                    asyncCallbackInfo->option, asyncCallbackInfo->valueStr);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniGetBundlePriorityConfig(ani_env* env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniGetBundlePriorityConfig called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = GET_BUNDLE_PRIORITY_CONFIG;
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::GetBundlePriorityConfig(
                    asyncCallbackInfo->option, asyncCallbackInfo->valueStr);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetPriorityEnabledByBundle(ani_env* env, ani_object obj, ani_enum_item enableStatus,
    ani_object callback)
{
    ANS_LOGD("AniSetPriorityEnabledByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::EnumConvertAniToNative(env, enableStatus, asyncCallbackInfo->status)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse enableStatus failed.");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed.");
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

    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetPriorityEnabledByBundle(
                    asyncCallbackInfo->option, asyncCallbackInfo->status);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsPriorityEnabledByBundle(ani_env* env, ani_object obj, ani_object callback)
{
    ANS_LOGD("AniIsPriorityEnabledByBundle called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    if (!NotificationSts::UnwrapBundleOption(env, obj, asyncCallbackInfo->option)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "UnwrapBundleOption failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_PRIORITY_ENABLED_BY_BUNDLE;
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::IsPriorityEnabledByBundle(
                    asyncCallbackInfo->option, asyncCallbackInfo->status);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniSetPriorityEnabled(ani_env* env, ani_boolean enable, ani_object callback)
{
    ANS_LOGD("AniSetPriorityEnabled called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->isPriorityEnabled = NotificationSts::AniBooleanToBool(enable);
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::SetPriorityEnabled(asyncCallbackInfo->isPriorityEnabled);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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

ani_object AniIsPriorityEnabled(ani_env* env, ani_object callback)
{
    ANS_LOGD("AniIsPriorityEnabled called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackPriorityInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->functionType = IS_PRIORITY_ENABLED;
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
            auto asyncCallbackInfo = static_cast<AsyncCallbackPriorityInfo*>(data);
            if (asyncCallbackInfo) {
                asyncCallbackInfo->info.returnCode =
                    Notification::NotificationHelper::IsPriorityEnabled(asyncCallbackInfo->isPriorityEnabled);
            }
        },
        HandlePriorityFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
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


void AniSetPriorityEnabledByBundles(ani_env *env, ani_object obj)
{
    std::vector<std::pair<Notification::NotificationBundleOption, bool>> options;
    if (NotificationSts::UnwrapBundleOptionMap(env, obj, options) != ANI_OK) {
        ANS_LOGE("UnwrapBundleOptionMap faild");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    std::map<sptr<Notification::NotificationBundleOption>, bool> priorityEnable;
    for (auto& [bundleOpt, enabled] : options) {
        sptr<Notification::NotificationBundleOption> bo =
            new (std::nothrow) Notification::NotificationBundleOption(std::move(bundleOpt));
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            return;
        }
        priorityEnable.emplace(bo, enabled);
    }
    int returnCode = Notification::NotificationHelper::SetPriorityEnabledByBundles(priorityEnable);
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts setPriorityEnabledByBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetPriorityEnabledByBundles end");
    return;
}

ani_object AniGetPriorityEnabledByBundles(ani_env *env, ani_object obj)
{
    std::vector<Notification::NotificationBundleOption> bundles;
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, bundles)) {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetPriorityEnabledByBundles failed : ERROR_INTERNAL_ERROR");
        return nullptr;
    }
 
    std::map<sptr<Notification::NotificationBundleOption>, bool> bundleEnable;
    int returnCode = Notification::NotificationHelper::GetPriorityEnabledByBundles(
        bundles, bundleEnable);
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts getPriorityEnabledByBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapBundleOptionMap(env, outAniObj, bundleEnable)) {
        ANS_LOGE("WrapBundleOptionMap faild");
        NotificationSts::ThrowInternerErrorWithLogE(
            env, "AniGetPriorityEnabledByBundles:failed to WrapBundleOptionMap");
        return nullptr;
    }
    return outAniObj;
}

void AniSetPriorityIntelligentEnabled(ani_env* env, ani_boolean enable)
{
    int returnCode =
        Notification::NotificationHelper::SetPriorityIntelligentEnabled(NotificationSts::AniBooleanToBool(enable));
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts setPriorityIntelligentEnabled failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_boolean AniIsPriorityIntelligentEnabled(ani_env *env, ani_object obj)
{
    bool enable = true;
    int returnCode = Notification::NotificationHelper::IsPriorityIntelligentEnabled(enable);
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts isPriorityIntelligentEnabled failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    return NotificationSts::BoolToAniBoolean(enable);
}

void AniSetPriorityStrategyByBundles(ani_env *env, ani_object obj)
{
    std::vector<std::pair<Notification::NotificationBundleOption, int64_t>> options;
    if (NotificationSts::UnwrapBundleOptionMap(env, obj, options) != ANI_OK) {
        ANS_LOGE("UnwrapBundleOptionMap faild");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    std::map<sptr<Notification::NotificationBundleOption>, int64_t> priorityStrategies;
    for (auto& [bundleOpt, strategy] : options) {
        sptr<Notification::NotificationBundleOption> bo =
            new (std::nothrow) Notification::NotificationBundleOption(std::move(bundleOpt));
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            return;
        }
        priorityStrategies.emplace(bo, strategy);
    }
    int returnCode = Notification::NotificationHelper::SetPriorityStrategyByBundles(priorityStrategies);
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts SetPriorityStrategyByBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_object AniGetPriorityStrategyByBundles(ani_env *env, ani_object obj)
{
    std::vector<Notification::NotificationBundleOption> bundles;
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, bundles)) {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetPriorityStrategyByBundles failed : ERROR_INTERNAL_ERROR");
        return nullptr;
    }
 
    std::map<sptr<Notification::NotificationBundleOption>, int64_t> priorityStrategies;
    int returnCode = Notification::NotificationHelper::GetPriorityStrategyByBundles(
        bundles, priorityStrategies);
    if (returnCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returnCode);
        ANS_LOGE("sts getPriorityEnabledByBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapBundleOptionMap(env, outAniObj, priorityStrategies)) {
        ANS_LOGE("WrapBundleOptionMap faild");
        NotificationSts::ThrowInternerErrorWithLogE(
            env, "AniGetPriorityStrategyByBundles:failed to WrapBundleOptionMap");
        return nullptr;
    }
    return outAniObj;
}
} // namespace NotificationManagerSts
} // namespace OHOS