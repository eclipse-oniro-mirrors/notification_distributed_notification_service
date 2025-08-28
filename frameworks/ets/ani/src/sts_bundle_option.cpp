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
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnwrapBundleOption failed, has nullptr");
        return false;
    }
    std::string tempStr;
    ani_boolean isUndefined = ANI_TRUE;
    if (GetPropertyString(env, obj, "bundle", isUndefined, tempStr) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapBundleOption Get bundle failed");
        return false;
    }
    std::string bundleName = GetResizeStr(tempStr, STR_MAX_SIZE);
    option.SetBundleName(bundleName);
    ani_int result = 0;
    if (GetPropertyInt(env, obj, "uid", isUndefined, result) == ANI_OK && isUndefined == ANI_FALSE) {
        int32_t uid = static_cast<int32_t>(result);
        option.SetUid(uid);
    } else {
        ANS_LOGD("UnwrapBundleOption get uid failed");
    }
    ANS_LOGD("UnwrapBundleOption end");
    return true;
}

ani_object GetAniArrayBundleOption(ani_env* env,
    const std::vector<BundleOption> &bundleOptions)
{
    ANS_LOGD("GetAniArrayActionButton call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayActionButton failed, has nullptr");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, bundleOptions.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayActionButton: arrayObj is nullptr");
        return nullptr;
    }
    int32_t index = 0;
    for (auto &option : bundleOptions) {
        std::shared_ptr<BundleOption> optSp = std::make_shared<BundleOption>(option);
        ani_object item;
        if (!WrapBundleOption(env, optSp, item) || item == nullptr) {
            ANS_LOGE("GetAniArrayActionButton: item is nullptr");
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", index, item)) {
            ANS_LOGE("GetAniArrayActionButton: Object_CallMethodByName_Void failed");
            return nullptr;
        }
        index ++;
    }
    ANS_LOGD("GetAniArrayActionButton end");
    return arrayObj;
}

bool UnwrapArrayBundleOption(ani_env *env,
    ani_ref arrayObj, std::vector<Notification::NotificationBundleOption>& options)
{
    ANS_LOGD("UnwrapArrayBundleOption call");
    if (env == nullptr || arrayObj == nullptr) {
        ANS_LOGE("UnwrapArrayBundleOption failed, has nullptr");
        return false;
    }
    ani_status status;
    ani_int length;
    status = env->Object_GetPropertyByName_Int(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("UnwrapArrayBundleOption: get length failed, status = %{public}d", status);
        return false;
    }
    Notification::NotificationBundleOption option;
    for (int32_t i = 0; i < length; i++) {
        ani_ref optionRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "i:C{std.core.Object}", &optionRef, i);
        if (status != ANI_OK) {
            ANS_LOGE("UnwrapArrayBundleOption: get bundleOptionRef failed, status = %{public}d", status);
            return false;
        }
        if (!UnwrapBundleOption(env, static_cast<ani_object>(optionRef), option)) {
            ANS_LOGE("UnwrapArrayBundleOption: get option status = %{public}d, index = %{public}d", status, i);
            return false;
        }
        options.push_back(option);
    }
    ANS_LOGD("UnwrapArrayBundleOption end");
    return true;
}

bool WrapBundleOption(ani_env* env,
    const std::shared_ptr<BundleOption> &bundleOption, ani_object &bundleObject)
{
    ANS_LOGD("WrapBundleOption call");
    if (env == nullptr || bundleOption == nullptr) {
        ANS_LOGE("WrapBundleOption failed, has nullptr");
        return false;
    }
    ani_class bundleCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.NotificationCommonDef.BundleOptionInner", bundleCls, bundleObject)
        || bundleCls == nullptr || bundleObject == nullptr) {
        ANS_LOGE("WrapBundleOption: create BundleOption failed");
        return false;
    }
    // bundle: string;
    ani_string stringValue = nullptr;
    if (ANI_OK != GetAniStringByString(env, bundleOption->GetBundleName(), stringValue)
        || !CallSetter(env, bundleCls, bundleObject, "bundle", stringValue)) {
        ANS_LOGE("WrapBundleOption: set bundle failed");
        return false;
    }
    // uid?: int;
    int32_t uid = bundleOption->GetUid();
    SetPropertyOptionalByInt(env, bundleObject, "uid", uid);
    ANS_LOGD("WrapBundleOption end");
    return true;
}
}
}
