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
#include "sts_disturb_mode.h"

#include "sts_bundle_option.h"
#include "sts_common.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
bool UnwrapDoNotDisturbProfile(ani_env *env, ani_object param,
    sptr<NotificationDoNotDisturbProfile> &profile)
{
    ANS_LOGD("UnwrapDoNotDisturbProfile call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("UnwrapDoNotDisturbProfile fail, has nullptr");
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_long idAni = 0;
    if (ANI_OK != env->Object_GetPropertyByName_Long(param, "id", &idAni)) {
        ANS_LOGE("UnwrapDoNotDisturbProfile: get id failed");
        return false;
    }
    profile->SetProfileId(static_cast<int64_t>(idAni));
    std::string nameStr = "";
    if (ANI_OK != GetPropertyString(env, param, "name", isUndefined, nameStr) || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapDoNotDisturbProfile: get name failed");
        return false;
    }
    profile->SetProfileName(nameStr);
    ani_ref trustlistRef;
    if (ANI_OK != GetPropertyRef(env, param, "trustlist", isUndefined, trustlistRef) || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapDoNotDisturbProfile: get trustlist failed");
    } else {
        std::vector<BundleOption> trustlist = {};
        UnwrapArrayBundleOption(env, static_cast<ani_object>(trustlistRef), trustlist);
        if (!trustlist.empty()) {
            profile->SetProfileTrustList(trustlist);
        }
    }
    ANS_LOGD("UnwrapDoNotDisturbProfile end");
    return true;
}

bool UnwrapArrayDoNotDisturbProfile(ani_env *env, ani_object arrayObj,
    std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("UnwrapArrayDoNotDisturbProfile call");
    if (env == nullptr || arrayObj == nullptr) {
        ANS_LOGE("UnwrapArrayDoNotDisturbProfile fail, has nullptr");
        return false;
    }
    ani_status status;
    ani_int length;
    status = env->Object_GetPropertyByName_Int(arrayObj, "length", &length);
    if (status != ANI_OK) {
        ANS_LOGD("UnwrapArrayDoNotDisturbProfile: status = %{public}d", status);
        return false;
    }
    for (int32_t i = 0; i < length; i++) {
        ani_ref optionRef;
        status = env->Object_CallMethodByName_Ref(arrayObj, "$_get",
            "i:C{std.core.Object}", &optionRef, i);
        if (status != ANI_OK) {
            ANS_LOGE("UnwrapArrayDoNotDisturbProfile: status : %{public}d, index: %{public}d", status, i);
            return false;
        }
        sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow)NotificationDoNotDisturbProfile();
        if (!UnwrapDoNotDisturbProfile(env, static_cast<ani_object>(optionRef), profile)) {
            ANS_LOGE("Get profile failed, index: %{public}d", i);
            return false;
        }
        profiles.push_back(profile);
    }
    ANS_LOGD("UnwrapArrayDoNotDisturbProfile end");
    return true;
}

bool WrapProfileTrustList(ani_env* env, sptr<NotificationDoNotDisturbProfile> profile,
    ani_object &outObj)
{
    ani_status status = ANI_OK;
    const auto& trustList = profile->GetProfileTrustList();
    if (trustList.empty()) {
        ANS_LOGE("WrapProfileTrustList trustlist is nullptr");
        return true;
    }
    ani_object arrayObj = newArrayClass(env, trustList.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("WrapProfileTrustList Failed to create trustlist array");
        return false;
    }

    int32_t index = 0;
    for (const auto& bundle : trustList) {
        auto bundlePtr = std::make_shared<Notification::NotificationBundleOption>(bundle);
        ani_object bundleObj = nullptr;
        if (!WrapBundleOption(env, bundlePtr, bundleObj)) {
            ANS_LOGE("WrapProfileTrustList WrapBundleOption failed");
            return false;
        }
        if (ANI_OK != (status = env->Object_CallMethodByName_Void(arrayObj, "$_set",
            "iC{std.core.Object}:", index, bundleObj))) {
            ANS_LOGE("WrapProfileTrustList set object faild. index %{public}d status %{public}d",
                index, status);
            return false;
        }
        index++;
    }
    ani_ref arrayRef = arrayObj;
    if (!SetPropertyByRef(env, outObj, "trustlist", arrayRef)) {
        ANS_LOGE("WrapProfileTrustList Failed to set trustlist property");
        return false;
    }
    return true;
}

bool WrapDoNotDisturbProfile(ani_env* env, sptr<NotificationDoNotDisturbProfile> profile,
    ani_object &outObj)
{
    ani_status status = ANI_OK;
    ani_class cls = nullptr;
    if (env == nullptr) {
        ANS_LOGE("WrapDoNotDisturbProfile: Invalid input parameters");
        return false;
    }
    const char* className = "@ohos.notificationManager.notificationManager.DoNotDisturbProfileInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj) || outObj == nullptr) {
        ANS_LOGE("WrapDoNotDisturbProfile: Failed to create profile class object");
        return false;
    }
    ani_long id = static_cast<ani_long>(profile->GetProfileId());
    if (ANI_OK != (status = env->Object_SetPropertyByName_Long(outObj, "id", id))) {
        ANS_LOGE("WrapDoNotDisturbProfile : set reason faild. status %{public}d", status);
        return false;
    }
    if (!SetPropertyOptionalByString(env, outObj, "name", profile->GetProfileName())) {
        ANS_LOGE("WrapDoNotDisturbProfile: set name failed");
        return false;
    }
    if (!WrapProfileTrustList(env, profile, outObj)) {
        ANS_LOGE("WrapDoNotDisturbProfile: set trustList failed");
        return false;
    }
    return true;
}
} // namespace NotificationSts
} // OHOS
