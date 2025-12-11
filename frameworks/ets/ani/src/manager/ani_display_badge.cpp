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
#include "ani_display_badge.h"

#include "ans_log_wrapper.h"
#include "sts_bundle_option.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_helper.h"
#include "notification_bundle_option.h"
#include "sts_convert_other.h"
#include "sts_badge_query_callback.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable)
{
    ANS_LOGD("DisplayBadgeAni call");
    int returncode = 0;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
        returncode = Notification::NotificationHelper::SetShowBadgeEnabledForBundle(option,
            NotificationSts::AniBooleanToBool(enable));
    } else {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("sts DisplayBadge ERROR_INTERNAL_ERROR");
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts DisplayBadge error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return;
    }
    ANS_LOGD("DisplayBadgeAni end");
}

ani_boolean AniIsBadgeDisplayed(ani_env *env, ani_object obj)
{
    ANS_LOGD("sts IsBadgeDisplayed call");
    int returncode = 0;
    bool isDisplayed = false;
    if (obj == nullptr) {
        returncode = Notification::NotificationHelper::GetShowBadgeEnabled(isDisplayed);
    } else {
        BundleOption option;
        if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
            returncode = Notification::NotificationHelper::GetShowBadgeEnabledForBundle(option, isDisplayed);
        } else {
            OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
                NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
            ANS_LOGE("sts IsBadgeDisplayed ERROR_INTERNAL_ERROR");
            return NotificationSts::BoolToAniBoolean(false);
        }
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts IsBadgeDisplayed error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("sts IsBadgeDisplayed end, isDisplayed: %{public}d", isDisplayed);
    return NotificationSts::BoolToAniBoolean(isDisplayed);
}

void AniSetBadgeNumber(ani_env *env, ani_int badgeNumber)
{
    ANS_LOGD("sts AniSetBadgeNumber call, BadgeNumber: %{public}d", badgeNumber);
    int returncode = Notification::NotificationHelper::SetBadgeNumber(static_cast<int32_t>(badgeNumber));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGD("sts AniSetBadgeNumber error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("sts AniSetBadgeNumber end");
}

void AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_int badgeNumber)
{
    ANS_LOGD("AniSetBadgeNumberByBundle call, badgeNumber: %{public}d", badgeNumber);
    int returncode = ERR_OK;
    BundleOption option;
    if (NotificationSts::UnwrapBundleOption(env, obj, option)) {
        returncode = Notification::NotificationHelper::SetBadgeNumberByBundle(option,
            badgeNumber);
    } else {
        ANS_LOGE("sts AniSetBadgeNumberByBundle ERROR_INTERNAL_ERROR");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGD("sts AniSetBadgeNumberByBundle error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetBadgeNumberByBundle end");
}

ani_status GetBadgesFromAni(ani_env *env, ani_object obj,
    std::vector<std::pair<Notification::NotificationBundleOption, bool>> &badges)
{
    ANS_LOGD("GetBadgesFromAni enter");
    ani_boolean isUndefined;
    ani_status status = ANI_ERROR;

    status = env->Reference_IsUndefined(obj, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGE("Failed to check undefined, status: %{public}d", status);
        return ANI_ERROR;
    }
    if (isUndefined == ANI_TRUE) {
        return ANI_ERROR;
    }

    ani_class mapClass;
    if (env->FindClass("Lstd/core/Map;", &mapClass) != ANI_OK) {
        ANS_LOGE("Find Map class failed.");
        return ANI_ERROR;
    }
    ani_type typeMap = mapClass;
    ani_boolean isMap;
    status = env->Object_InstanceOf(obj, typeMap, &isMap);
    if (isMap != ANI_TRUE) {
        ANS_LOGE("Current obj is not map type.");
        return ANI_ERROR;
    }

    if (NotificationSts::GetMapByAniMap(env, obj, badges) != ANI_OK) {
        return ANI_ERROR;
    }
    ANS_LOGD("GetBadgesFromAni end");
    return ANI_OK;
}

void AniSetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj)
{
    std::vector<std::pair<Notification::NotificationBundleOption, bool>> options;
    if (GetBadgesFromAni(env, obj, options) != ANI_OK) {
        ANS_LOGE("GetBadgesFromAni faild");
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        return;
    }
    int returncode = Notification::NotificationHelper::SetShowBadgeEnabledForBundles(options);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("sts BatchSetBadgeDisplayStatus error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetBadgeDisplayStatusByBundles end");
    return;
}

bool WrapBadges(ani_env *env, ani_object &outAniObj,
    const std::map<sptr<Notification::NotificationBundleOption>, bool> &bundleEnable)
{
    ANS_LOGD("WrapBadges enter");
    outAniObj = nullptr;
    outAniObj = NotificationSts::CreateMapObject(env, "Lstd/core/Map;", ":V");
    if (outAniObj == nullptr) {
        return false;
    }
    ani_ref mapRef = nullptr;
    ani_status status = ANI_ERROR;
    for (const auto& [k, v] : bundleEnable) {
        ani_object bundleObj;
        if (!NotificationSts::WrapBundleOption(env, k, bundleObj) || bundleObj == nullptr) {
            ANS_LOGE("WrapNotificationBadgeInfo: WrapBundleOption failed");
            continue;
        }
        ani_object enable = NotificationSts::CreateBoolean(env, v);
        status = env->Object_CallMethodByName_Ref(outAniObj, "set",
            "Lstd/core/Object;Lstd/core/Object;:Lstd/core/Map;", &mapRef,
            static_cast<ani_object>(bundleObj), static_cast<ani_object>(enable));
        if (status != ANI_OK) {
            ANS_LOGE("Faild to set bundleEnable map, status : %{public}d", status);
            continue;
        }
    }
    if (outAniObj == nullptr) {
        return false;
    }
    ANS_LOGD("WrapBadges end");
    return true;
}

ani_object AniGetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj)
{
    ani_status status = ANI_ERROR;
    std::vector<Notification::NotificationBundleOption> bundles;
    if (!NotificationSts::UnwrapArrayBundleOption(env, obj, bundles)) {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetBadgeDisplayStatusByBundles failed : ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    std::map<sptr<Notification::NotificationBundleOption>, bool> bundleEnable;
    int returncode = Notification::NotificationHelper::GetShowBadgeEnabledForBundles(
        bundles, bundleEnable);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetBadgeDisplayStatusByBundles error, errorCode: %{public}d", externalCode);
        return nullptr;
    }
    ani_object outAniObj;
    if (!WrapBadges(env, outAniObj, bundleEnable)) {
        ANS_LOGE("WrapNotificationSlotArray faild");
        NotificationSts::ThrowErrorWithMsg(env, "AniGetSlots:failed to WrapNotificationSlotArray");
        return nullptr;
    }
    return outAniObj;
}

ani_long AniGetBadgeNumber(ani_env *env)
{
    ANS_LOGD("sts AniGetBadgeNumber call");
    int32_t num = 0;
    int returncode = OHOS::Notification::NotificationHelper::GetBadgeNumber(num);
    ANS_LOGD("sts AniGetBadgeNumber end, badgenumber: %{public}d", num);
    ani_long retNum = static_cast<ani_long>(num);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetBadgeNumber error, errorCode: %{public}d", externalCode);
        return 0;
    }
    return retNum;
}

void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn)
{
    ANS_LOGD("AniOnBadgeNumberQuery enter");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOnBadgeNumberQuery(env, fn);
}

void AniOffBadgeNumberQuery(ani_env *env)
{
    ANS_LOGD("AniOffBadgeNumberQuery enter");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniOffBadgeNumberQuery(env);
}

void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num)
{
    ANS_LOGD("AniHandleBadgeNumberPromise enter");
    OHOS::NotificationSts::StsBadgeQueryCallBackManager::GetInstance()->AniHandleBadgeNumberPromise(env, bundle, num);
}
}
}
