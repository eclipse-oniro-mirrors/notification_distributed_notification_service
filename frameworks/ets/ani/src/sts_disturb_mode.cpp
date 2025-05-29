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
    ani_double idAni = 0.0;
    if (ANI_OK != env->Object_GetPropertyByName_Double(param, "id", &idAni)) {
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
    ani_double length;
    status = env->Object_GetPropertyByName_Double(arrayObj, "length", &length);
    if (status != ANI_OK) {
        ANS_LOGD("UnwrapArrayDoNotDisturbProfile: status = %{public}d", status);
        return false;
    }
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref optionRef;
        status = env->Object_CallMethodByName_Ref(arrayObj, "$_get",
            "I:Lstd/core/Object;", &optionRef, (ani_int)i);
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
} // namespace NotificationSts
} // OHOS