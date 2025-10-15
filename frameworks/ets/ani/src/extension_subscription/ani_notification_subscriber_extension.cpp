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
void AniSubscribe(ani_env *env, ani_object notificationInfoArrayobj)
{
    ANS_LOGD("AniSubscribe call");
    std::vector<sptr<Notification::NotificationExtensionSubscriptionInfo>> infos;
    if (!NotificationSts::UnwarpNotificationExtensionSubscribeInfoArrayByAniObj(env, notificationInfoArrayobj, infos)) {
        ANS_LOGE("UnwrapNotificationSlotArrayByAniObj failed");
        NotificationSts::ThrowErrorWithMsg(env, "sts Subscribe ERROR_INTERNAL_ERROR");
        return;
    }
    
    int returncode = Notification::NotificationHelper::NotificationExtensionSubscribe(infos);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSubscribe error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniSubscribe end");
}

void AniUnsubscribe(ani_env *env)
{
    ANS_LOGD("AniUnsubscribe enter");
    int returncode = Notification::NotificationHelper::NotificationExtensionUnsubscribe();
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniUnsubscribe failed, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("AniUnsubscribe end");
}

ani_object AniGetSubscribeInfo(ani_env *env)
{
    ANS_LOGD("AniGetSubscribeInfo enter");
    int returncode = ERR_OK;
    std::vector<sptr<Notification::NotificationExtensionSubscriptionInfo>> infos;
    returncode = Notification::NotificationHelper::GetSubscribeInfo(infos);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetSubscribeInfo error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_object outAniObj;
    if (!NotificationSts::WrapNotificationExtensionSubscribeInfoArray(env, infos, outAniObj)) {
        NotificationSts::ThrowErrorWithMsg(
            env, "AniGetSubscribeInfo:failed to WrapNotificationExtensionSubscribeInfoArray");
        return nullptr;
    }
    ANS_LOGD("AniGetSubscribeInfo end");
    return outAniObj;
}

ani_object AniGetAllSubscriptionBundles(ani_env *env)
{
    ANS_LOGD("AniGetAllSubscriptionBundles enter");
    int returncode = ERR_OK;
    std::vector<sptr<BundleOption>> bundles;
    returncode = Notification::NotificationHelper::GetAllSubscriptionBundles(bundles);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetAllSubscriptionBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    std::vector<BundleOption> plainBundles;
    for (const auto& sptrBundle : bundles) {
        if (sptrBundle != nullptr) {
            plainBundles.emplace_back(*sptrBundle);
        }
    }
    bundles.clear();

    ani_object arrayBundles = NotificationSts::GetAniArrayBundleOption(env, plainBundles);
    if (arrayBundles == nullptr) {
        ANS_LOGE("AniGetAllSubscriptionBundles filed, arrayBundles is nullptr");
        NotificationSts::ThrowErrorWithMsg(env, "AniGetAllSubscriptionBundles ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    ANS_LOGD("AniGetAllSubscriptionBundles end");
    return arrayBundles;
}

ani_boolean AniIsUserGranted(ani_env *env)
{
    ANS_LOGD("AniIsUserGranted call");
    int returncode = ERR_OK;
    bool enabled = false;
    returncode = Notification::NotificationHelper::IsUserGranted(enabled);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniIsUserGranted error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return ANI_FALSE;
    }
    ANS_LOGD("AniIsUserGranted end");
    return NotificationSts::BoolToAniBoolean(enabled);
}

ani_boolean AniGetUserGrantedState(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniGetUserGrantedState call");
    int returncode = ERR_OK;
    bool enabled = false;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::GetUserGrantedState(option, enabled);
    } else {
        NotificationSts::ThrowErrorWithMsg(env, "sts GetUserGrantedState ERROR_INTERNAL_ERROR");
        return ANI_FALSE;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetUserGrantedState error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return ANI_FALSE;
    }
    ANS_LOGD("AniGetUserGrantedState end");
    return NotificationSts::BoolToAniBoolean(enabled);
}

void AniSetUserGrantedState(ani_env *env, ani_object bundleOption, ani_boolean enable)
{
    ANS_LOGD("AniSetUserGrantedState call");
    BundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        NotificationSts::ThrowErrorWithMsg(env, "sts SetUserGrantedState ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = Notification::NotificationHelper::SetUserGrantedState(option,
        NotificationSts::AniBooleanToBool(enable));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniSetUserGrantedState error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetUserGrantedState end");
}

ani_object AniGetUserGrantedEnableBundles(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniGetUserGrantedEnableBundles enter");
    int returncode = ERR_OK;
    std::vector<sptr<BundleOption>> bundles;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        returncode = Notification::NotificationHelper::GetUserGrantedEnabledBundles(option, bundles);
    } else {
        NotificationSts::ThrowErrorWithMsg(env, "sts GetUserGrantedEnableBundles ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetUserGrantedEnableBundles error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }

    std::vector<BundleOption> plainBundles;
    for (const auto& sptrBundle : bundles) {
        if (sptrBundle != nullptr) {
            plainBundles.emplace_back(*sptrBundle);
        }
    }
    bundles.clear();

    ani_object arrayBundles = NotificationSts::GetAniArrayBundleOption(env, plainBundles);
    if (arrayBundles == nullptr) {
        ANS_LOGE("AniGetUserGrantedEnableBundles filed, arrayBundles is nullptr");
        NotificationSts::ThrowErrorWithMsg(env, "AniGetUserGrantedEnableBundles ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    ANS_LOGD("AniGetUserGrantedEnableBundles end");
    return arrayBundles;
}

ani_object AniGetUserGrantedEnableBundlesForSelf(ani_env *env)
{
    ANS_LOGD("AniGetUserGrantedEnableBundlesForSelf enter");
    int returncode = ERR_OK;
    std::vector<sptr<BundleOption>> bundles;
    returncode = Notification::NotificationHelper::GetUserGrantedEnabledBundlesForSelf(bundles);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniGetUserGrantedEnableBundlesForSelf error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }

    std::vector<std::string> bundleNames;
    for (const auto& bundle : bundles) {
        bundleNames.emplace_back(bundle->GetBundleName());
    }
    ani_object arrayBundles = NotificationSts::GetAniStringArrayByVectorString(env, bundleNames);
    if (arrayBundles == nullptr) {
        ANS_LOGE("AniGetUserGrantedEnableBundlesForSelf failed, arrayBundles is nullptr");
        NotificationSts::ThrowErrorWithMsg(env, "AniGetUserGrantedEnableBundlesForSelf ERROR_INTERNAL_ERROR");
        return nullptr;
    }
    return arrayBundles;
}

void AniSetUserGrantedBundleState(ani_env *env, ani_object bundleOption, ani_object bundles, ani_boolean enabled)
{
    ANS_LOGD("AniSetUserGrantedBundleState enter");
    int returncode = ERR_OK;
    std::vector<BundleOption> bundlesArray;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        if (NotificationSts::UnwrapArrayBundleOption(env, bundles, bundlesArray)) {
            std::vector<sptr<BundleOption>> sptrBundlesArray;
            for (const auto& bundle : bundlesArray) {
                sptrBundlesArray.emplace_back(new BundleOption(bundle));
            }
            returncode = Notification::NotificationHelper::SetUserGrantedBundleState(
                option, sptrBundlesArray, NotificationSts::AniBooleanToBool(enabled));
        } else {
            NotificationSts::ThrowErrorWithMsg(
                env, "sts SetUserGrantedBundleState UnwrapArrayBundleOption ERROR_INTERNAL_ERROR");
            return;
        }
    } else {
        NotificationSts::ThrowErrorWithMsg(
            env, "sts SetUserGrantedBundleState UnwrapBundleOption ERROR_INTERNAL_ERROR");
        return;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniSetUserGrantedBundleState error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetUserGrantedBundleState end");
}
} // namespace NotificationExtensionSubScriptionSts
} // namespace OHOS