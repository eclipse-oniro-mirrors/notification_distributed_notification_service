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
#include "sts_common.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
constexpr const char* CLASSNAME_BOOLEAN = "Lstd/core/Boolean;";
constexpr const char* CLASSNAME_DOUBLE = "Lstd/core/Double;";

ani_status GetAniStringByString(ani_env* env, const std::string str, ani_string& aniStr)
{
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        ANS_LOGE("String_NewUTF8 failed %{public}d", status);
        return status;
    }
    return status;
}

ani_status GetStringByAniString(ani_env *env, ani_string str, std::string &res)
{
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        ANS_LOGD("status : %{public}d", status);
        return status;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        ANS_LOGD("status : %{public}d", status);
        return status;
    }
    res.resize(sz);
    return status;
}

ani_status GetPropertyString(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, std::string &outStr)
{
    ani_status status = ANI_ERROR;
    ani_ref strRef;
    if ((status =env->Object_GetPropertyByName_Ref(obj, name, &strRef)) != ANI_OK) {
        ANS_LOGD("Object_GetField_Ref bundle fail, status: %{public}d", status);
        return status;
    }
    status = env->Reference_IsUndefined(strRef, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGD("Failed to check undefined for '%{public}s', status: %{public}d", name, status);
        return status;
    }
    if(isUndefined == ANI_TRUE) {
        ANS_LOGI("%{public}s is undefined", name);
        return status;
    }
    if ((status = GetStringByAniString(env, reinterpret_cast<ani_string>(strRef), outStr)) != ANI_OK) {
        ANS_LOGD("GetStdString failed");
        return status;
    }
    return status;
}

ani_status GetPropertyBool(ani_env *env, ani_object obj, const char *name,
    ani_boolean isUndefined, bool outvalue)
{
    ani_ref refObj = nullptr;
    ani_status status = ANI_ERROR;
    ani_ref uidRef;
    status = env->Object_GetPropertyByName_Ref(obj, name, &uidRef);
    if (ANI_OK != status) {
        ANS_LOGD("Object_GetPropertyByName_Ref fail, status: %{public}d", status);
        return status;
    }
    if ((status = env->Reference_IsUndefined(uidRef, &isUndefined)) != ANI_OK) {
        ANS_LOGD("Reference_IsUndefined failed, status : %{public}d", status);
        return status;
    }
    if (isUndefined) {
        ANS_LOGI("%{public}s is undefined", name);
        return ANI_INVALID_ARGS;
    }
    ani_boolean result = ANI_FALSE;
    if ((status = env->Object_CallMethodByName_Boolean(static_cast<ani_object>(refObj),
        "unboxed", ":Z", &result)) != ANI_OK) {
        ANS_LOGD("Object_CallMethodByName_Boolean failed, status : %{public}d", status);
        return status;
    }
    outvalue = (result == ANI_TRUE);
    return status;
}

ani_status GetPropertyDouble(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_double &outvalue)
{
    ani_status status = ANI_ERROR;
    ani_ref uidRef;
    if ((status = env->Object_GetPropertyByName_Ref(obj, name, &uidRef)) != ANI_OK) {
        ANS_LOGI("Object_GetPropertyByName_Ref fail, status: %{public}d", status);
        return status;
    }
    if ((status = env->Reference_IsUndefined(uidRef, &isUndefined)) == ANI_OK) {
        ANS_LOGI("Reference_IsUndefined failed, status : %{public}d", status);
        return status;
    }
    if (isUndefined) {
        ANS_LOGI("%{public}s is undefined", name);
        return ANI_INVALID_ARGS;
    }
    status = env->Object_CallMethodByName_Double(static_cast<ani_object>(uidRef), "doubleValue", nullptr, &outvalue);
    if (ANI_OK != status) {
        ANS_LOGI("Object_CallMethodByName_Double uid fail, status: %{public}d", status);
        return status;
    }
    return status;
}

ani_status GetPropertyRef(ani_env *env, ani_object obj, const char *name, ani_boolean &isUndefined, ani_ref &outRef)
{
    ani_status status = env->Object_GetPropertyByName_Ref(obj, name, &outRef);
    if (status != ANI_OK) {
        ANS_LOGI("Failed to get property '%{public}s', status: %{public}d", name, status);
        return status;
    }
    status = env->Reference_IsUndefined(outRef, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGI("Failed to check undefined for '%{public}s', status: %{public}d", name, status);
    }
    return status;
}

ani_status GetStringArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<std::string> &res)
{
    ani_ref arrayObj = nullptr;
    ani_status status;
    ani_double length;
    std::string str;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }

    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }

        str = "";
        status = GetStringByAniString(env, static_cast<ani_string>(stringEntryRef), str);
        if (status != ANI_OK) {
            ANS_LOGI("GetStdString failed, index: %{public}d", i);
            return status;
        }

        res.push_back(str);
        ANS_LOGI("GetStdString index: %{public}d %{public}s", i, str.c_str());
    }
    return status;
}

ani_object GetAniStringArrayByVectorString(ani_env *env, std::vector<std::string> &strs)
{
    if (strs.empty()) {
        return nullptr;
    }
    int length = strs.size();
    ani_object arrayObj = newArrayClass(env, length);
    ani_size i = 0;
    for (auto &str : strs) {
        ani_string aniStr;
        RETURN_NULL_IF_FALSE(GetAniStringByString(env, str, aniStr) != ANI_OK);
        if (aniStr == nullptr) {
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, aniStr);
        if (status != ANI_OK) {
            ANS_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
        i++;
    }
    return arrayObj;
}

bool SetFieldString(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, const std::string value)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(cls);
    RETURN_FALSE_IF_NULL(object);
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);

    ANS_LOGD("SetFieldString fieldName : %{public}s", fieldName.c_str());

    if (status != ANI_OK) {
        ANS_LOGE("SetFieldString status : %{public}d", status);
        return false;
    }

    if (value.empty()) {
        ani_ref nullRef = nullptr;
        if ((status = env->GetNull(&nullRef)) != ANI_OK) {
            ANS_LOGE("SetFieldString GetNull fail status : %{public}d", status);
            return false;
        }
        if ((status = env->Object_SetField_Ref(object, field, nullRef)) != ANI_OK) {
            ANS_LOGE("SetFieldString Object_SetField_Ref fail status : %{public}d", status);
            return false;
        }
        return true;
    }

    if ((status = env->String_NewUTF8(value.c_str(), value.size(), &string)) != ANI_OK) {
        ANS_LOGE("SetFieldString String_NewUTF8 fail status : %{public}d", status);
        return false;
    }

    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        ANS_LOGE("SetFieldString Object_SetField_Ref fail status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetOptionalFieldBoolean(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, bool value)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(cls);
    RETURN_FALSE_IF_NULL(object);
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_object boolObj = CreateBoolean(env, BoolToAniBoolean(value));
    RETURN_FALSE_IF_NULL(boolObj);
    status = env->Object_SetField_Ref(object, field, boolObj);
    if (status != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}

bool SetOptionalFieldDouble(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, double value)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(cls);
    RETURN_FALSE_IF_NULL(object);
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_object doubleObj = CreateDouble(env, value);
    RETURN_FALSE_IF_NULL(doubleObj);
    status = env->Object_SetField_Ref(object, field, doubleObj);
    if (status != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}

ani_object CreateBoolean(ani_env *env, bool value)
{
    ani_class boolCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_BOOLEAN, &boolCls)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_method boolCtor;
    if ((status = env->Class_FindMethod(boolCls, "<ctor>", "Z:V", &boolCtor)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object boolObj;
    if ((status = env->Object_New(boolCls, boolCtor, &boolObj, value ? ANI_TRUE : ANI_FALSE))
       != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    return boolObj;
}

ani_object CreateDouble(ani_env *env, double value)
{
    ani_class doubleCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_DOUBLE, &doubleCls)) != ANI_OK) {
        ANS_LOGE( "status : %{public}d", status);
        return nullptr;
    }
    ani_method doubleCtor;
    if ((status = env->Class_FindMethod(doubleCls, "<ctor>", "D:V", &doubleCtor)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object doubleObj;
    if ((status = env->Object_New(doubleCls, doubleCtor, &doubleObj, static_cast<ani_double>(value))) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    return doubleObj;
}

ani_object newArrayClass(ani_env *env, int length)
{
    ANS_LOGD("newArrayClass call");
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)){
        ANS_LOGE("FindClass Lescompat/Array; Failed");
        return nullptr;
    }
    ani_method arrayCtor;
    if(ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)){
        ANS_LOGE("Class_FindMethod <ctor> Failed");
        return nullptr;
    }
    ani_object arrayObj = nullptr;
    if(ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, length)){
        ANS_LOGE("Object_New Array Faild");
        return arrayObj;
    }
    ANS_LOGD("newArrayClass end");
    return arrayObj;
}

ani_object newRecordClass(ani_env *env)
{
    ANS_LOGD("newRecordClass call");
    ani_class recordCls;
    ani_method ctor;
    if (ANI_OK != env->FindClass("Lescompat/Record;", &recordCls)) {
        return nullptr;
    }

    if (ANI_OK != env->Class_FindMethod(recordCls, "<ctor>", nullptr, &ctor)) {
        return nullptr;
    }
    ani_object recordObj = {};
    if (ANI_OK != env->Object_New(recordCls, ctor, &recordObj)) {
        return nullptr;
    }
    ANS_LOGD("newRecordClass end");
    return recordObj;
}

ani_object ConvertArrayDoubleToAniObj(ani_env *env, const std::vector<std::int64_t> values)
{
    if (values.empty()) {
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, values.size());
    if (arrayObj == nullptr) {
        return nullptr;
    }

    for (size_t i = 0; i < values.size(); i++) {
        ani_object intObj = CreateDouble(env, static_cast<double>(values[i]));
        if (intObj == nullptr) {
            ANS_LOGE("null intObj");
            return nullptr;
        }
        ani_status status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, intObj);
        if (status != ANI_OK) {
            ANS_LOGE("status : %{public}d", status);
            return nullptr;
        }
    }
    return arrayObj;
}

bool SetOptionalFieldArrayDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
    const std::vector<std::int64_t> &values)
{
    if (values.empty()) {
        return false;
    }
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return false;
    }

    ani_object arrayObj = ConvertArrayDoubleToAniObj(env, values);
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is nullptr.");
        return false;
    }
    status = env->Object_SetField_Ref(object, field, arrayObj);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return false;
    }
    return true;
}

bool CreateClassObjByClassName(ani_env *env, const char *className, ani_class &cls, ani_object &outAniObj)
{
    ANI_FAILED_AND_RETURN(env->FindClass(className, &cls));
    ani_method ctor;
    ANI_FAILED_AND_RETURN(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor));
    outAniObj = {};
    ANI_FAILED_AND_RETURN(env->Object_New(cls, ctor, &outAniObj));
    return true;
}
} // namespace NotificationSts
} // OHOS