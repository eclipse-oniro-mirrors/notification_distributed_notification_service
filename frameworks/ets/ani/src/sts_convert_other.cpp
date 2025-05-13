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
#include "sts_convert_other.h"

#include "sts_common.h"
#include "pixel_map_ani.h"

namespace OHOS {
namespace NotificationSts {
void UnwrapWantAgent(ani_env *env, ani_object agent, void** result)
{
    ANS_LOGI("called");
    if (agent == nullptr) {
        ANS_LOGI("agent null");
        return;
    }
    ani_long param_value;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    ani_method method {};
    if ((status = env->FindClass("Lstd/core/Long;", &cls)) != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, "unboxed", nullptr, &method)) != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return;
    }
    if ((status = env->Object_CallMethod_Long(agent, method, &param_value)) != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return;
    }
    *result = reinterpret_cast<void*>(param_value);
}

ani_status UnwrapResource(ani_env *env, ani_object obj, ResourceManager::Resource resource)
{
    ani_status status = ANI_ERROR;
    std::string bundleName = "";
    ani_boolean isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "bundleName", isUndefined, bundleName)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    resource.bundleName = bundleName;

    std::string moduleName = "";
    if((status = GetPropertyString(env, obj, "moduleName", isUndefined, moduleName)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    resource.moduleName = moduleName;

    ani_double idAni = 0.0;
    if((status = GetPropertyDouble(env, obj, "id", isUndefined, idAni)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    resource.id = static_cast<int32_t>(idAni);
    return status;
}

ani_object CreateAniPixelMap(ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    if (pixelMap == nullptr) {
        return nullptr;
    }
    return PixelMapAni::CreatePixelMap(env, pixelMap);
}

std::shared_ptr<PixelMap> GetPixelMapFromEnvSp(ani_env* env, ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        ANS_LOGI("[GetPixelMapFromEnv] Object_GetField_Long fetch failed");
        return nullptr;
    }
    PixelMapAni* pixelmapAni = reinterpret_cast<PixelMapAni*>(nativeObj);
    if (!pixelmapAni) {
        ANS_LOGI("[GetPixelMapFromEnv] pixelmapAni nullptr");
        return nullptr;
    }
    return pixelmapAni->nativePixelMap_;
}

ani_status GetPixelMapArrayByRef(ani_env *env, ani_ref param, std::vector<std::shared_ptr<PixelMap>> &pixelMaps)
{
    ani_status status = ANI_ERROR;
    ani_double length;
    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(param), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref pixelMapRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(param),
            "$_get", "I:Lstd/core/Object;", &pixelMapRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(pixelMapRef));
        if (pixelMap == nullptr) {
           return ANI_INVALID_ARGS;
        }
        pixelMaps.push_back(pixelMap);
    }
    return status;
}

ani_status GetPixelMapArray(ani_env *env, 
    ani_object param, const char *name, std::vector<std::shared_ptr<PixelMap>> &pixelMaps)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = ANI_TRUE;
    ani_status status = ANI_ERROR;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }

    if ((status = GetPixelMapArrayByRef(env, arrayObj, pixelMaps)) != ANI_OK) {
        return status;
    }
    return status;
}

ani_status GetResourceArray(ani_env *env, 
    ani_object param, const char *name, std::vector<ResourceManager::Resource> &res)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_double length;

    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }

    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref iconRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &iconRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        
        ResourceManager::Resource resource;
        if(ANI_OK != UnwrapResource(env, static_cast<ani_object>(iconRef), resource)) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        res.push_back(resource);
    }
    return status;
}

ani_status GetKeyString(ani_env *env, ani_object obj, int index, ani_string &str)
{
    ani_status status = ANI_ERROR;
    ani_ref stringEntryRef;
    status = env->Object_CallMethodByName_Ref(obj,
        "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)index);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d, index: %{public}d", status, index);
        return status;
    }
    str = static_cast<ani_string>(stringEntryRef);
    return status;
}

ani_status GetPixelMapByKeys(ani_env *env, ani_object obj, std::vector<ani_string> keys,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ani_status status = ANI_ERROR;
    for(auto anikey : keys) {
        ani_ref picturesArrayRef;
        if (ANI_OK != (status = env->Object_CallMethodByName_Ref(obj, "$_get", nullptr, &picturesArrayRef, anikey))) {
            return status;
        }
        std::vector<std::shared_ptr<PixelMap>> pixelMaps = {};
        if((status = GetPixelMapArrayByRef(env, picturesArrayRef, pixelMaps)) != ANI_OK) {
            return status;
        }
        std::string str = "";
        if((status = GetStringByAniString(env, anikey, str)) != ANI_OK) {
            return status;
        }
        pictureMap[str] = pixelMaps;
    }
    return status;
}

ani_status GetMapOfPictureInfo(ani_env *env, ani_object obj,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap)
{
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    RETURN_ANI_STATUS_IF_NOT_OK(status = env->FindClass("Lnotification/notificationContent/RecordTools;", &cls),
        "failed to find class -> Lnotification/notificationContent/RecordTools;");
    if (cls == nullptr) {
        return ANI_INVALID_TYPE;
    }
    ani_static_method keysMethod = nullptr;
    RETURN_ANI_STATUS_IF_NOT_OK(status = env->Class_FindStaticMethod(cls, "GetKeys", nullptr, &keysMethod),
        "find Method GetKeys failed.");
    ani_ref keysStrArrayRef = nullptr;
    RETURN_ANI_STATUS_IF_NOT_OK(status = env->Class_CallStaticMethod_Ref(cls, keysMethod, &keysStrArrayRef, obj),
        "failed to call method GetKeys");
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(keysStrArrayRef, &isUndefined)) != ANI_OK) {
        return status;
    }
    if (isUndefined) {
        return ANI_INVALID_ARGS;
    }
    ani_double length;
    RETURN_ANI_STATUS_IF_NOT_OK(
        status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(keysStrArrayRef), "length", &length),
        "get length ok keys failed.");
    ani_string strAni = {};
    std::vector<ani_string> keys = {};
    for (int i = 0; i < static_cast<int>(length); i++) {
        if((status = GetKeyString(env, static_cast<ani_object>(keysStrArrayRef), i, strAni)) != ANI_OK) {
            return status;
        }
        keys.push_back(strAni);
    }
    status = GetPixelMapByKeys(env, obj, keys, pictureMap);
    return status;
}

ani_object GetAniResource(ani_env *env, const std::shared_ptr<ResourceManager::Resource> &resource)
{
    ani_class resourceCls = nullptr;
    ani_object resourceObject = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "Lglobal/resource/ResourceInner;", resourceCls, resourceObject));
    // bundleName: string;
    ani_string stringValue = nullptr;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, resource->bundleName, stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, resourceCls, resourceObject, "bundleName", stringValue));
    // moduleName: string;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, resource->moduleName, stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, resourceCls, resourceObject, "moduleName", stringValue));
    // id: number;
    RETURN_NULL_IF_FALSE(CallSetter(env, resourceCls, resourceObject, "id", resource->id));
    return resourceObject;
}

ani_object GetAniArrayPixelMap(ani_env *env, const std::vector<std::shared_ptr<Media::PixelMap>> &pixelMaps)
{
    RETURN_NULL_IF_NULL(env);
    if (pixelMaps.empty()) {
        return nullptr;
    }

    ani_size length = pixelMaps.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size i = 0;
    for (auto &pixelMap : pixelMaps) {
        ani_object pixelMapObject = Media::PixelMapAni::CreatePixelMap(env, pixelMap);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("CreatePixelMap failed, pixelMapObject is nullptr");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, pixelMapObject);
        if (status != ANI_OK) {
            ANS_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    return arrayObj;
}

ani_object GetAniArrayResource(ani_env *env,
    const std::vector<std::shared_ptr<ResourceManager::Resource>> &resources)
{
    RETURN_NULL_IF_NULL(env);
    if (resources.empty()) {
        ANS_LOGE("resources is empty");
        return nullptr;
    }
    
    ani_size length = resources.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size i = 0;
    for (auto &resource : resources) {
        ani_object resourceObject = GetAniResource(env, resource);
        if (resourceObject == nullptr) {
            ANS_LOGE("GetAniResource failed, resourceObject is nullptr");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, resourceObject);
        if (status != ANI_OK) {
            ANS_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    return arrayObj;
}

bool GetAniPictrueInfo(ani_env *env, std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap,
    ani_object &pictureInfoObj)
{
    if (pictureMap.empty()) {
        return false;
    }
    pictureInfoObj = newRecordClass(env);
    for (const auto& [key, value] : pictureMap) {
        ani_string aniKey;
        if(GetAniStringByString(env, key, aniKey) != ANI_OK || aniKey == nullptr) {
            return false;
        }
        ani_object aniPictrueArray = GetAniArrayPixelMap(env, value);
        if (aniPictrueArray == nullptr) {
            return false;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(pictureInfoObj,
            "$_set", "Lstd/core/Object;Lstd/core/Object;:V", aniKey, aniPictrueArray)) {
            return false;
        }
    }
    return true;
}

ani_object WarpWantAgent(ani_env *env, std::shared_ptr<WantAgent> wantAgent)
{
    if (wantAgent == nullptr) {
        return nullptr;
    }
    return AppExecFwk::WrapWantAgent(env, wantAgent.get());
}

ani_object GetAniWantAgentArray(ani_env *env, std::vector<std::shared_ptr<WantAgent>> wantAgents)
{
    ani_status status = ANI_ERROR;
    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_object arrayObj;
    status = env->FindClass("Lescompat/Array;", &arrayCls);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, wantAgents.size());
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_size index = 0;
    for (auto &wantAgent : wantAgents) {
        ani_object item = AppExecFwk::WrapWantAgent(env, wantAgent.get());
        RETURN_NULL_IF_NULL(item);
        if(ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)){
           std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
           return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}
} // namespace NotificationSts
} // OHOS