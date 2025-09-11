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
#include "pixel_map_taihe_ani.h"

namespace OHOS {
namespace NotificationSts {
std::shared_ptr<WantAgent> UnwrapWantAgent(ani_env *env, ani_object agent)
{
    ANS_LOGD("UnwrapWantAgent called");
    if (env == nullptr || agent == nullptr) {
        ANS_LOGE("UnwrapWantAgent failed, has nullPtr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_long nativeObj {};
    if ((status = env->Object_GetFieldByName_Long(agent, "nativeObj", &nativeObj)) != ANI_OK) {
        ANS_LOGI("UnwrapWantAgent Object_GetField_Long fetch failed, status = %{public}d", status);
        return nullptr;
    }
    WantAgent* wantAgent = reinterpret_cast<WantAgent*>(nativeObj);
    if (wantAgent == nullptr) {
        ANS_LOGI("UnwrapWantAgent wantAgent nullptr");
        return nullptr;
    }
    std::shared_ptr<WantAgent> wantAgentSp = std::make_shared<WantAgent>(*wantAgent);
    deletePoint(wantAgent);
    ANS_LOGD("UnwrapWantAgent end");
    return wantAgentSp;
}

ani_status UnwrapResource(ani_env *env, ani_object obj, ResourceManager::Resource &resource)
{
    ANS_LOGD("UnwrapResource called");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnwrapResource failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    std::string tempStr = "";
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = GetPropertyString(env, obj, "bundleName", isUndefined, tempStr)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    std::string bundleName = GetResizeStr(tempStr, STR_MAX_SIZE);
    resource.bundleName = bundleName;

    if ((status = GetPropertyString(env, obj, "moduleName", isUndefined, tempStr)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    std::string moduleName = GetResizeStr(tempStr, STR_MAX_SIZE);
    resource.moduleName = moduleName;

    ani_double idAni = 0.0;
    if ((status = GetPropertyDouble(env, obj, "id", isUndefined, idAni)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    resource.id = static_cast<int32_t>(idAni);
    ANS_LOGD("UnwrapResource end");
    return status;
}

ani_object CreateAniPixelMap(ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    ANS_LOGD("CreateAniPixelMap call");
    if (env == nullptr || pixelMap == nullptr) {
        ANS_LOGE("CreateAniPixelMap failed, has nullPtr");
        return nullptr;
    }
    return PixelMapTaiheAni::CreateEtsPixelMap(env, pixelMap);
}

std::shared_ptr<PixelMap> GetPixelMapFromAni(ani_env* env, ani_object obj)
{
    ANS_LOGD("GetPixelMapFromAni call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("GetPixelMapFromAni failed, has nullPtr");
        return nullptr;
    }
    return PixelMapTaiheAni::GetNativePixelMap(env, obj);
}

ani_status GetPixelMapArrayByRef(ani_env *env, ani_ref param,
    std::vector<std::shared_ptr<PixelMap>> &pixelMaps, const uint32_t maxLen)
{
    ANS_LOGD("GetPixelMapArrayByRef call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("GetPixelMapArrayByRef failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_double length;
    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(param), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("GetPixelMapArrayByRef: status : %{public}d", status);
        return status;
    }
    if (maxLen > 0 && length > maxLen) {
        length = static_cast<ani_int>(maxLen);
    }
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref pixelMapRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(param),
            "$_get", "I:Lstd/core/Object;", &pixelMapRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGE("GetPixelMapArrayByRef:status : %{public}d, index: %{public}d", status, i);
            pixelMaps.clear();
            return status;
        }
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromAni(env, static_cast<ani_object>(pixelMapRef));
        if (pixelMap == nullptr) {
            ANS_LOGE("GetPixelMapArrayByRef: GetPixelMapFromAni failed.");
            pixelMaps.clear();
            return ANI_INVALID_ARGS;
        }
        pixelMaps.push_back(pixelMap);
    }
    ANS_LOGD("GetPixelMapArrayByRef end");
    return status;
}

ani_status GetPixelMapArray(ani_env *env, ani_object param, const char *name,
    std::vector<std::shared_ptr<PixelMap>> &pixelMaps, const uint32_t maxLen)
{
    ANS_LOGD("GetPixelMapArray call");
    if (env == nullptr || param == nullptr || name == nullptr) {
        ANS_LOGE("GetPixelMapArray failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = ANI_TRUE;
    ani_status status = ANI_ERROR;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }

    if ((status = GetPixelMapArrayByRef(env, arrayObj, pixelMaps, maxLen)) != ANI_OK) {
        pixelMaps.clear();
        return status;
    }
    ANS_LOGD("GetPixelMapArray end");
    return status;
}

ani_status GetResourceArray(ani_env *env, ani_object param, const char *name,
    std::vector<ResourceManager::Resource> &res, const uint32_t maxLen)
{
    ANS_LOGD("GetResourceArray call");
    if (env == nullptr || param == nullptr || name == nullptr) {
        ANS_LOGE("GetResourceArray failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_double length;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetResourceArray failed, status : %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("GetResourceArray : status : %{public}d", status);
        return status;
    }
    if (length > maxLen) {
        length = static_cast<ani_int>(maxLen);
    }
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref iconRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &iconRef, (ani_int)i);
        if (status != ANI_OK) {
            res.clear();
            ANS_LOGE("GetResourceArray: status = %{public}d, index = %{public}d", status, i);
            return status;
        }
        ResourceManager::Resource resource;
        if (ANI_OK != UnwrapResource(env, static_cast<ani_object>(iconRef), resource)) {
            ANS_LOGE("GetResourceArray : status = %{public}d, index= %{public}d", status, i);
            res.clear();
            return status;
        }
        res.push_back(resource);
    }
    ANS_LOGD("GetResourceArray end");
    return status;
}

ani_status GetKeyString(ani_env *env, ani_object obj, int index, ani_string &str)
{
    ANS_LOGD("GetKeyString call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("GetKeyString failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_ref stringEntryRef;
    status = env->Object_CallMethodByName_Ref(obj,
        "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)index);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d, index: %{public}d", status, index);
        return status;
    }
    str = static_cast<ani_string>(stringEntryRef);
    ANS_LOGD("GetKeyString end");
    return status;
}

ani_status GetPixelMapByKeys(ani_env *env, ani_object obj, std::vector<ani_string> keys,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ANS_LOGD("GetPixelMapByKeys call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("GetPixelMapByKeys failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    for (auto anikey : keys) {
        ani_ref picturesArrayRef;
        if (ANI_OK != (status = env->Object_CallMethodByName_Ref(obj, "$_get", nullptr, &picturesArrayRef, anikey))) {
            ANS_LOGE("GetPixelMapByKeys :  Object_CallMethodByName_Ref failed");
            deleteVectorWithArraySpPoints(pictureMap);
            return status;
        }
        std::vector<std::shared_ptr<PixelMap>> pixelMaps = {};
        if ((status = GetPixelMapArrayByRef(env, picturesArrayRef, pixelMaps)) != ANI_OK) {
            ANS_LOGE("GetPixelMapByKeys :  GetPixelMapArrayByRef failed");
            deleteVectorWithSpPoints(pixelMaps);
            deleteVectorWithArraySpPoints(pictureMap);
            return status;
        }
        std::string str = "";
        if ((status = GetStringByAniString(env, anikey, str)) != ANI_OK) {
            ANS_LOGE("GetPixelMapByKeys :  GetStringByAniString failed");
            deleteVectorWithSpPoints(pixelMaps);
            deleteVectorWithArraySpPoints(pictureMap);
            return status;
        }
        pictureMap[str] = pixelMaps;
    }
    ANS_LOGD("GetPixelMapByKeys end");
    return status;
}

ani_status GetPixelMapByRef(
    ani_env *env, ani_object obj, ani_ref keysStrArrayRef,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ANS_LOGD("GetPixelMapByRef call");
    if (env == nullptr || obj == nullptr || keysStrArrayRef == nullptr) {
        ANS_LOGE("GetPixelMapByRef failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_double length;
    if (ANI_OK !=
        (status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(keysStrArrayRef), "length", &length))) {
        ANS_LOGE("GetPixelMapByRef : Object_GetPropertyByName_Double status = %{public}d", status);
        return status;
    }
    ani_string strAni = {};
    std::vector<ani_string> keys = {};
    for (int i = 0; i < static_cast<int>(length); i++) {
        if ((status = GetKeyString(env, static_cast<ani_object>(keysStrArrayRef), i, strAni)) != ANI_OK) {
            ANS_LOGE("GetPixelMapByRef : GetKeyString status = %{public}d", status);
            keys.clear();
            return status;
        }
        keys.push_back(strAni);
    }
    status = GetPixelMapByKeys(env, obj, keys, pictureMap);
    ANS_LOGD("GetPixelMapByRef end");
    return status;
}

ani_status GetMapOfPictureInfo(ani_env *env, ani_object obj,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ANS_LOGD("GetMapOfPictureInfo call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("GetMapOfPictureInfo failed, has nullPtr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if (ANI_OK != (status = env->FindClass("Lnotification/notificationContent/RecordTools;", &cls))) {
        ANS_LOGE("GetMapOfPictureInfo : FindClass status = %{public}d", status);
        return status;
    }
    if (cls == nullptr) {
        ANS_LOGE("GetMapOfPictureInfo : cls is nullptr");
        return ANI_INVALID_TYPE;
    }
    ani_static_method keysMethod = nullptr;
    if (ANI_OK != (status = env->Class_FindStaticMethod(cls, "GetKeys", nullptr, &keysMethod))) {
        ANS_LOGE("GetMapOfPictureInfo : Class_FindStaticMethod status = %{public}d", status);
        return status;
    }
    ani_ref keysStrArrayRef = nullptr;
    if (ANI_OK != (status = env->Class_CallStaticMethod_Ref(cls, keysMethod, &keysStrArrayRef, obj))) {
        ANS_LOGE("GetMapOfPictureInfo : Class_CallStaticMethod_Ref status = %{public}d", status);
        return status;
    }
    if (IsUndefine(env, static_cast<ani_object>(keysStrArrayRef))) {
        ANS_LOGE("GetMapOfPictureInfo : keysStrArrayRef IsUndefined");
        return ANI_INVALID_ARGS;
    }
    if (ANI_OK != (status = GetPixelMapByRef(env, obj, keysStrArrayRef, pictureMap))) {
        deleteVectorWithArraySpPoints(pictureMap);
        ANS_LOGE("GetMapOfPictureInfo : GetPixelMapByRef status = %{public}d", status);
    }
    ANS_LOGD("GetMapOfPictureInfo end");
    return status;
}

ani_object GetAniResource(ani_env *env, const std::shared_ptr<ResourceManager::Resource> resource)
{
    ANS_LOGD("GetAniResource call");
    if (env == nullptr || resource == nullptr) {
        ANS_LOGE("GetAniResource failed, has nullPtr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class resourceCls = nullptr;
    ani_object resourceObject = nullptr;
    if (!CreateClassObjByClassName(env,
        "Lglobal/resourceInner/ResourceInner;", resourceCls, resourceObject)) {
        ANS_LOGE("GetAniResource : CreateClassObjByClassName failed");
        return nullptr;
    }
    ani_string stringValue = nullptr;
    if (ANI_OK != (status = GetAniStringByString(env, resource->bundleName, stringValue))
        || !CallSetter(env, resourceCls, resourceObject, "bundleName", stringValue)) {
        ANS_LOGE("GetAniResource : set bundleName failed, status = %{public}d", status);
        return nullptr;
    }
    if (ANI_OK != (status = GetAniStringByString(env, resource->moduleName, stringValue))
        || !CallSetter(env, resourceCls, resourceObject, "moduleName", stringValue)) {
        ANS_LOGE("GetAniResource : set moduleName failed, status = %{public}d", status);
        return nullptr;
    }
    if (!CallSetter(env, resourceCls, resourceObject, "id", resource->id)) {
        ANS_LOGE("GetAniResource : set moduleName failed, status = %{public}d", status);
    }
    ANS_LOGD("GetAniResource end");
    return resourceObject;
}

ani_object GetAniArrayPixelMap(ani_env *env, const std::vector<std::shared_ptr<Media::PixelMap>> pixelMaps)
{
    ANS_LOGD("GetAniArrayPixelMap call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayPixelMap failed, env is nullPtr");
        return nullptr;
    }
    ani_size length = pixelMaps.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayPixelMap : arrayObj is nullptr");
        return nullptr;
    }
    ani_size i = 0;
    for (auto pixelMap : pixelMaps) {
        ani_object pixelMapObject = CreateAniPixelMap(env, pixelMap);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("GetAniArrayPixelMap : pixelMapObject is nullptr");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, pixelMapObject);
        if (status != ANI_OK) {
            ANS_LOGE("GetAniArrayPixelMap : Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    ANS_LOGD("GetAniArrayPixelMap end");
    return arrayObj;
}

ani_object GetAniArrayResource(ani_env *env,
    const std::vector<std::shared_ptr<ResourceManager::Resource>> resources)
{
    ANS_LOGD("GetAniArrayResource call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayResource failed, env is nullPtr");
        return nullptr;
    }
    ani_size length = resources.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayResource : arrayObj is nullPtr");
        return nullptr;
    }
    ani_size i = 0;
    for (auto resource : resources) {
        ani_object resourceObject = GetAniResource(env, resource);
        if (resourceObject == nullptr) {
            ANS_LOGE("GetAniArrayResource : resourceObject is nullPtr");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, resourceObject);
        if (status != ANI_OK) {
            ANS_LOGE("GetAniArrayResource : Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    ANS_LOGD("GetAniArrayResource end");
    return arrayObj;
}

bool GetAniPictrueInfo(ani_env *env, std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap,
    ani_object &pictureInfoObj)
{
    ANS_LOGD("GetAniPictrueInfo call");
    if (env == nullptr) {
        ANS_LOGE("GetAniPictrueInfo failed, env is nullPtr");
        return false;
    }
    pictureInfoObj = newRecordClass(env);
    if (pictureInfoObj == nullptr) {
        ANS_LOGE("GetAniPictrueInfo failed, pictureInfoObj is nullPtr");
        return false;
    }
    for (const auto& [key, value] : pictureMap) {
        ani_string aniKey;
        if (GetAniStringByString(env, key, aniKey) != ANI_OK || aniKey == nullptr) {
            ANS_LOGE("GetAniPictrueInfo : GetAniStringByString failed");
            return false;
        }
        ani_object aniPictrueArray = GetAniArrayPixelMap(env, value);
        if (aniPictrueArray == nullptr) {
            ANS_LOGE("GetAniPictrueInfo : GetAniArrayPixelMap failed");
            return false;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(pictureInfoObj,
            "$_set", "Lstd/core/Object;Lstd/core/Object;:V", aniKey, aniPictrueArray)) {
            ANS_LOGE("GetAniPictrueInfo : Object_CallMethodByName_Void failed");
            return false;
        }
    }
    ANS_LOGD("GetAniPictrueInfo end");
    return true;
}

ani_object WarpWantAgent(ani_env *env, std::shared_ptr<WantAgent> wantAgent)
{
    ANS_LOGD("WarpWantAgent call");
    if (wantAgent == nullptr) {
        ANS_LOGE("WarpWantAgent failed, wantAgent is nullptr");
        return nullptr;
    }
    ani_object wantAgentObj = AppExecFwk::WrapWantAgent(env, wantAgent.get());
    if (wantAgentObj == nullptr) {
        ANS_LOGE("WarpWantAgent : wantAgentObj is nullptr");
    }
    ANS_LOGD("WarpWantAgent end");
    return wantAgentObj;
}

ani_object GetAniWantAgentArray(ani_env *env, std::vector<std::shared_ptr<WantAgent>> wantAgents)
{
    ANS_LOGD("GetAniWantAgentArray call");
    if (env == nullptr || wantAgents.empty()) {
        ANS_LOGE("GetAniWantAgentArray failed, env is nullptr or wantAgents is empty");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class arrayCls = nullptr;
    if (ANI_OK != (status = env->FindClass("Lescompat/Array;", &arrayCls))) {
        ANS_LOGE("GetAniWantAgentArray : FindClass status = %{public}d", status);
        return nullptr;
    }
    ani_method arrayCtor;
    if (ANI_OK != (status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor))) {
        ANS_LOGE("GetAniWantAgentArray : Class_FindMethod status = %{public}d", status);
        return nullptr;
    }
    ani_object arrayObj;
    if (ANI_OK != (status = env->Object_New(arrayCls, arrayCtor, &arrayObj, wantAgents.size()))) {
        ANS_LOGE("GetAniWantAgentArray : Object_New status = %{public}d", status);
        return nullptr;
    }
    ani_size index = 0;
    for (auto &wantAgent : wantAgents) {
        ani_object item = WarpWantAgent(env, wantAgent);
        if (item == nullptr
            || ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)) {
            ANS_LOGE("GetAniWantAgentArray : set WantAgent failed");
            return nullptr;
        }
        index ++;
    }
    ANS_LOGD("GetAniWantAgentArray end");
    return arrayObj;
}

ani_object CreateAniUndefined(ani_env *env)
{
    ani_ref aniRef;
    env->GetUndefined(&aniRef);
    return reinterpret_cast<ani_object>(aniRef);
}
 
ani_object CreateMapObject(ani_env *env, const std::string name, const char *signature)
{
    ani_class cls = nullptr;
    if (env->FindClass(name.c_str(), &cls) != ANI_OK) {
        ANS_LOGE("Failed to found %{public}s", name.c_str());
        return nullptr;
    }
    ani_method ctor;
    if (env->Class_FindMethod(cls, "<ctor>", signature, &ctor) != ANI_OK) {
        ANS_LOGE("Failed to get ctor %{public}s", name.c_str());
        return nullptr;
    }
    ani_object obj = {};
    if (env->Object_New(cls, ctor, &obj) != ANI_OK) {
        ANS_LOGE("Failed to create object %{public}s", name.c_str());
        return nullptr;
    }
    return obj;
}
 
ani_status GetMapIterator(ani_env *env, ani_object &mapObj, const char *method, ani_ref *it)
{
    ani_status status = env->Object_CallMethodByName_Ref(mapObj, method, nullptr, it);
    if (status != ANI_OK) {
        ANS_LOGD("Failed to get %{public}s iterator, status: %{public}d", method, status);
    }
    return status;
}
 
ani_status GetMapIteratorNext(ani_env *env, ani_ref &it, ani_ref *next)
{
    ani_status status = env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(it), "next", nullptr, next);
    if (status != ANI_OK) {
        ANS_LOGD("Failed to get next, status: %{public}d", status);
    }
    return status;
}
 
ani_status GetMapIteratorStringValue(ani_env *env, ani_ref &next, std::string &str)
{
    ani_ref val;
    ani_status status = env->Object_GetFieldByName_Ref(reinterpret_cast<ani_object>(next), "value", &val);
    if (status != ANI_OK) {
        ANS_LOGD("Falied to get value, status: %{public}d", status);
    }
    status = GetStringByAniString(env, reinterpret_cast<ani_string>(val), str);
    if (status == ANI_OK && str.size() > STRUCTURED_TEXT_SIZE) {
        str.resize(STRUCTURED_TEXT_SIZE);
        ANS_LOGW("Structured text truncated to 512 bytes.");
    }
    return status;
}
 
ani_status GetMapByAniMap(ani_env *env, ani_object &mapObj,
    std::vector<std::pair<std::string, std::string>> &out)
{
    ani_status status = ANI_ERROR;
    ani_ref keys;
    ani_ref values;
    bool done = false;
 
    if (GetMapIterator(env, mapObj, "keys", &keys) != ANI_OK ||
        GetMapIterator(env, mapObj, "values", &values) != ANI_OK) {
        return ANI_ERROR;
    }
 
    while (!done) {
        ani_ref nextKey;
        ani_ref nextVal;
        ani_boolean done;
 
        if (GetMapIteratorNext(env, keys, &nextKey) != ANI_OK ||
            GetMapIteratorNext(env, values, &nextVal) != ANI_OK) {
            return ANI_ERROR;
        }
 
        if ((status = env->Object_GetFieldByName_Boolean(reinterpret_cast<ani_object>(nextKey), "done", &done))
            != ANI_OK) {
            ANS_LOGD("Failed to check iterator done, status: %{public}d", status);
            return ANI_ERROR;
        }
        if (done) {
            break;
        }
 
        std::string keyStr;
        std::string valStr;
        if (GetMapIteratorStringValue(env, nextKey, keyStr) != ANI_OK||
            GetMapIteratorStringValue(env, nextVal, valStr) != ANI_OK) {
            return ANI_ERROR;
        }
        ANS_LOGD("__logwd sts %{public}s %{public}s", keyStr.c_str(), valStr.c_str());
        out.emplace_back(keyStr, valStr);
    }
 
    return ANI_OK;
}
} // namespace NotificationSts
} // OHOS
