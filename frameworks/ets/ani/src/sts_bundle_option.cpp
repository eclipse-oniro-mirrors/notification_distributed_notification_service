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
namespace {
constexpr const char* BUNDLE_OPTION_CLASSNAME = "notification.NotificationCommonDef.BundleOptionInner";
constexpr const char* GRANTED_BUNDLE_INFO_CLASSNAME = "notification.NotificationCommonDef.GrantedBundleInfoInner";
}

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
    ani_array arrayObj = newArrayClass(env, bundleOptions.size());
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
        if (ANI_OK != env->Array_Set(arrayObj, index, item)) {
            ANS_LOGE("GetAniArrayActionButton: Array_Set failed");
            return nullptr;
        }
        index ++;
    }
    ANS_LOGD("GetAniArrayActionButton end");
    return arrayObj;
}

bool GetAniArrayBundleOptionV2(
    ani_env* env, const std::vector<sptr<BundleOption>>& bundleOptions, ani_object& outAniObj)
{
    ANS_LOGD("GetAniArrayBundleOptionV2 call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayBundleOptionV2 failed, has nullptr");
        return false;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(BUNDLE_OPTION_CLASSNAME, &cls);
    if (status != ANI_OK) {
        ANS_LOGE("FindClass failed. status : %{public}d", status);
        return false;
    }
    ani_array array = nullptr;
    size_t size = bundleOptions.size();
    status = env->Array_New(size, nullptr, &array);
    if (status != ANI_OK) {
        ANS_LOGE("Array_New_Ref failed. status : %{public}d", status);
        return false;
    }
    int32_t index = 0;
    for (auto& bundleOption : bundleOptions) {
        std::shared_ptr<BundleOption> optSp = std::make_shared<BundleOption>(*bundleOption);
        ani_object item;
        if (!WrapBundleOption(env, optSp, item) || item == nullptr) {
            ANS_LOGE("WrapBundleOption Failed. index = %{public}d", index);
            return false;
        }
        status = env->Array_Set(array, index, item);
        if (status != ANI_OK) {
            ANS_LOGE("Array_Set Failed. index = %{public}d, status = %{public}d", index, status);
            return false;
        }
        index++;
    }
    ANS_LOGD("GetAniArrayBundleOptionV2 end");
    outAniObj = array;
    return true;
}


bool SetAniArrayGrantedBundleInfo(
    ani_env* env, const std::vector<sptr<BundleOption>>& bundleOptions, ani_object& outAniObj)
{
    ANS_LOGD("call");
    if (env == nullptr) {
        ANS_LOGE("SetAniArrayGrantedBundleInfo failed, has nullptr");
        return false;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(GRANTED_BUNDLE_INFO_CLASSNAME, &cls);
    if (status != ANI_OK) {
        ANS_LOGE("FindClass failed. status : %{public}d", status);
        return false;
    }
    ani_array array = nullptr;
    size_t size = bundleOptions.size();
    status = env->Array_New(size, nullptr, &array);
    if (status != ANI_OK) {
        ANS_LOGE("Array_New_Ref failed. status : %{public}d", status);
        return false;
    }
    int32_t index = 0;
    for (auto& bundleOption : bundleOptions) {
        std::shared_ptr<BundleOption> optSp = std::make_shared<BundleOption>(*bundleOption);
        ani_object item;
        if (!WrapGrantedBundleInfo(env, optSp, item) || item == nullptr) {
            ANS_LOGE("WrapGrantedBundleInfo Failed. index = %{public}d", index);
            return false;
        }
        status = env->Array_Set(array, index, item);
        if (status != ANI_OK) {
            ANS_LOGE("Array_Set Failed. index = %{public}d, status = %{public}d", index, status);
            return false;
        }
        index++;
    }
    ANS_LOGD("end");
    outAniObj = array;
    return true;
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
    ani_array optionArray = static_cast<ani_array>(arrayObj);
    ani_size length;
    status = env->Array_GetLength(optionArray, &length);
    if (status != ANI_OK) {
        ANS_LOGE("Array_GetLength fail. status : %{public}d", status);
        return status;
    }
    int32_t arraySize = static_cast<int32_t>(length);
    for (int32_t i = 0; i < arraySize; i++) {
        ani_ref optionRef;
        status = env->Array_Get(optionArray, i, &optionRef);
        if (status != ANI_OK) {
            ANS_LOGE("UnwrapArrayBundleOption: get bundleOptionRef failed, status = %{public}d", status);
            return false;
        }
        Notification::NotificationBundleOption option;
        if (!UnwrapBundleOption(env, static_cast<ani_object>(optionRef), option)) {
            ANS_LOGE("UnwrapArrayBundleOption: get option status = %{public}d, index = %{public}d", status, i);
            return false;
        }
        options.push_back(option);
    }
    ANS_LOGD("UnwrapArrayBundleOption end");
    return true;
}

bool WrapGrantedBundleInfo(ani_env* env, const std::shared_ptr<BundleOption> &bundleOption, ani_object &bundleObject)
{
    ANS_LOGD("called");
    if (env == nullptr || bundleOption == nullptr) {
        ANS_LOGE("WrapGrantedBundleInfo failed, has nullptr");
        return false;
    }
    ani_class bundleCls = nullptr;
    if (!CreateClassObjByClassName(env, GRANTED_BUNDLE_INFO_CLASSNAME, bundleCls, bundleObject) ||
        bundleCls == nullptr || bundleObject == nullptr) {
        ANS_LOGE("WrapGrantedBundleInfo: create BundleOption failed");
        return false;
    }
    ani_string stringValue = nullptr;
    if (ANI_OK != GetAniStringByString(env, bundleOption->GetBundleName(), stringValue)
        || !CallSetter(env, bundleCls, bundleObject, "bundleName", stringValue)) {
        ANS_LOGE("WrapGrantedBundleInfo: set bundle failed");
        return false;
    }
    
    if (ANI_OK != GetAniStringByString(env, bundleOption->GetAppName(), stringValue)
        || !CallSetter(env, bundleCls, bundleObject, "appName", stringValue)) {
        ANS_LOGE("WrapGrantedBundleInfo: set appName failed");
        return false;
    }
    int32_t uid = bundleOption->GetAppIndex();
    SetPropertyOptionalByInt(env, bundleObject, "appIndex", uid);
    ANS_LOGD("end");
    return true;
}

bool WrapBundleOption(ani_env* env, const std::shared_ptr<BundleOption> &bundleOption, ani_object &bundleObject)
{
    ANS_LOGD("WrapBundleOption call");
    if (env == nullptr || bundleOption == nullptr) {
        ANS_LOGE("WrapBundleOption failed, has nullptr");
        return false;
    }
    ani_class bundleCls = nullptr;
    if (!CreateClassObjByClassName(env, BUNDLE_OPTION_CLASSNAME, bundleCls, bundleObject) ||
        bundleCls == nullptr || bundleObject == nullptr) {
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

bool WrapBundleOption(ani_env* env,
    const sptr<BundleOption> &bundleOption, ani_object &bundleObject)
{
    ANS_LOGD("WrapBundleOption call");
    if (env == nullptr || bundleOption == nullptr) {
        ANS_LOGE("WrapBundleOption failed, has nullptr");
        return false;
    }
    ani_class bundleCls = nullptr;
    if (!CreateClassObjByClassName(env, "notification.NotificationCommonDef.BundleOptionInner",
        bundleCls, bundleObject)
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

bool UnwrapDistributedBundleOption(ani_env *env, ani_object obj, DistributedBundleOption &distributedOption)
{
    ANS_LOGD("UnwrapDistributedBundleOption call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnwrapDistributedBundleOption failed, has nullptr");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    std::string tempStr;
    status = GetPropertyString(env, obj, "bundleName", isUndefined, tempStr);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyString 'bundleName' fail. status:%{public}d", status);
        return false;
    }
    std::shared_ptr<BundleOption> optionValue = std::make_shared<BundleOption>();
    if (optionValue == nullptr) {
        ANS_LOGE("new BundleOption fail.");
        return false;
    }
    std::string bundleName = GetResizeStr(tempStr, STR_MAX_SIZE);
    optionValue->SetBundleName(bundleName);
    ani_int result = 0;
    if ((status = env->Object_GetPropertyByName_Int(obj, "uid", &result)) != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Int 'uid' fail. status:%{public}d", status);
        return false;
    }
    optionValue->SetUid(result);
    distributedOption.SetBundle(optionValue);
    bool enable = true;
    status = GetPropertyBool(env, obj, "enable", isUndefined, enable);
    if (status == ANI_OK && isUndefined == ANI_FALSE) {
        distributedOption.SetEnable(enable);
    }
    ANS_LOGD("UnwrapDistributedBundleOption end");
    return true;
}

bool UnwrapArrayDistributedBundleOption(ani_env *env, ani_object arrayObj,
    std::vector<DistributedBundleOption> &options)
{
    ANS_LOGD("UnwrapArrayDistributedBundleOption call");
    if (env == nullptr || arrayObj == nullptr) {
        ANS_LOGE("UnwrapArrayDistributedBundleOption failed, has nullptr");
        return false;
    }
    ani_status status;
    ani_array optionArray = static_cast<ani_array>(arrayObj);
    ani_size length;
    status = env->Array_GetLength(optionArray, &length);
    if (status != ANI_OK) {
        ANS_LOGE("Array_GetLength fail. status : %{public}d", status);
        return status;
    }
    int32_t arraySize = static_cast<int32_t>(length);
    for (int32_t i = 0; i < arraySize; i++) {
        ani_ref optionRef;
        status = env->Array_Get(optionArray, i, &optionRef);
        if (status != ANI_OK) {
            ANS_LOGE("get optionRef failed, status = %{public}d", status);
            return false;
        }
        Notification::DistributedBundleOption option;
        if (!UnwrapDistributedBundleOption(env, static_cast<ani_object>(optionRef), option)) {
            ANS_LOGE("get option status = %{public}d, index = %{public}d", status, i);
            return false;
        }
        options.push_back(option);
    }
    ANS_LOGD("UnwrapArrayDistributedBundleOption end");
    return true;
}
}
}