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
#include "sts_bundle_option.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationSts {
bool UnwrapBundleOption(ani_env *env, ani_object obj, Notification::NotificationBundleOption& option)
{
    ANS_LOGD("UnwrapBundleOption call");
    std::string bundleName;
    ani_boolean isUndefined = ANI_ERROR;    
    if (GetPropertyString(env, obj, "bundle", isUndefined, bundleName) !=ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("get bundle failed, bundle must be string.");
        return false;
    }
    option.SetBundleName(bundleName);
    ani_double result = 0.0;
    if (GetPropertyDouble(env, obj, "uid", isUndefined, result) == ANI_OK && isUndefined == ANI_FALSE) {
        int32_t uid = static_cast<int32_t>(result);
        option.SetUid(uid);
    } else {
        ANS_LOGD("Wrong argument type or uid is Undefined.");
    }
    ANS_LOGD(
        "WrapBundleOption bundleName: %{public}s uid: %{public}d", option.GetBundleName().c_str(), option.GetUid());
    return true;
}

bool UnwrapArrayBundleOption(ani_env *env, ani_ref arrayObj, std::vector<Notification::NotificationBundleOption>& options)
{
    ani_status status;
    ani_double length;
    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return false;
    }

    Notification::NotificationBundleOption option;
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref optionRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lnotification/NotificationCommonDef/BundleOption;", &optionRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGD("status : %{public}d, index: %{public}d", status, i);
            deletePoint(optionRef);
            return false;
        }

        if (!UnwrapBundleOption(env, static_cast<ani_object>(optionRef), option)) {
            ANS_LOGD("Get BundleOption failed, index: %{public}d", i);
            deletePoint(optionRef);
            return false;
        }
        options.push_back(option);
        ANS_LOGD("GetOptions index: %{public}d", i);
        deletePoint(optionRef);
    }
    return true;
}

bool WrapBundleOption(ani_env* env,
    const std::shared_ptr<BundleOption> &bundleOption, ani_object &bundleObject)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("agentBundle is null");
        return false;
    }
    ani_class bundleCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "Lnotification/NotificationCommonDef/BundleOptionInner;", bundleCls, bundleObject)) {
        deletePoint(bundleCls);
        return false;
    }
    if (bundleCls == nullptr || bundleObject == nullptr) {
        deletePoint(bundleCls);
        deletePoint(bundleObject);
        return false;
    }
    // bundle: string;
    ani_string stringValue = nullptr;
    if (!GetAniStringByString(env, bundleOption->GetBundleName(), stringValue)) {
        deletePoint(bundleCls);
        deletePoint(bundleObject);
        deletePoint(stringValue);
        return false;
    }
    if (!CallSetter(env, bundleCls, bundleObject, "bundle", stringValue)) {
        deletePoint(bundleCls);
        deletePoint(bundleObject);
        deletePoint(stringValue);
        return false;
    }
    // uid?: number;
    uint32_t uid = bundleOption->GetUid();
    CallSetterOptional(env, bundleCls, bundleObject, "uid", uid);
    deletePoint(bundleCls);
    return true;
}
}
}