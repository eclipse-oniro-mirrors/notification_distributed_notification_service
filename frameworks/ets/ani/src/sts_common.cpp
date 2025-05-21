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
#include "ani_common_util.h"

namespace OHOS {
namespace NotificationSts {
constexpr const char* CLASSNAME_BOOLEAN = "Lstd/core/Boolean;";
constexpr const char* CLASSNAME_DOUBLE = "Lstd/core/Double;";
constexpr const char* CLASSNAME_INT = "Lstd/core/Int;";

bool IsUndefine(ani_env *env, const ani_object &obj)
{
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("IsUndefine fail, has nullptr");
        return true;
    }
    ani_boolean isUndefined;
    if (ANI_OK != env->Reference_IsUndefined(obj, &isUndefined)) {
        ANS_LOGE("Reference_IsUndefined  faild");
        return true;
    }
    return (isUndefined == ANI_TRUE) ? true : false;
}

ani_status GetAniStringByString(ani_env* env, const std::string str, ani_string& aniStr)
{
    if (env == nullptr) {
        ANS_LOGE("GetAniStringByString fail, env is nullptr");
        return ANI_INVALID_ARGS;
    }
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        ANS_LOGE("String_NewUTF8 failed %{public}d", status);
        return status;
    }
    return status;
}

ani_status GetStringByAniString(ani_env *env, ani_string str, std::string &res)
{
    if (str == nullptr || env == nullptr) {
        ANS_LOGE("GetStringByAniString fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return status;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return status;
    }
    res.resize(sz);
    return status;
}

bool GetStringArrayByAniObj(ani_env *env, const ani_object ani_obj, std::vector<std::string> &stdVString)
{
    if (env == nullptr || ani_obj == nullptr) {
        ANS_LOGE("GetStringArrayByAniObj fail, has nullptr");
        return false;
    }
    ani_double length;
    ani_status status = env->Object_GetPropertyByName_Double(ani_obj, "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Double faild. status %{public}d", status);
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(ani_obj,
            "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGE("status : %{public}d", status);
            return false;
        }
        std::string std_string;
        if (!GetStringByAniString(env, static_cast<ani_string>(stringEntryRef), std_string)) {
            ANS_LOGE("GetStdString faild");
            return false;
        }
        stdVString.emplace_back(std_string);
    }
    return true;
}

ani_status GetPropertyString(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, std::string &outStr)
{
    if (env == nullptr || obj == nullptr || name == nullptr) {
        ANS_LOGE("GetPropertyString fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("GetPropertyString: %{public}s", name);
    ani_status status = ANI_ERROR;
    ani_ref strRef;
    if ((status =env->Object_GetPropertyByName_Ref(obj, name, &strRef)) != ANI_OK) {
        ANS_LOGE("Object_GetField_Ref bundle fail, status: %{public}d", status);
        return status;
    }
    status = env->Reference_IsUndefined(strRef, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGE("Failed to check undefined for '%{public}s', status: %{public}d", name, status);
        return status;
    }
    if(isUndefined == ANI_TRUE) {
        ANS_LOGE("%{public}s is undefined", name);
        return status;
    }
    if ((status = GetStringByAniString(env, reinterpret_cast<ani_string>(strRef), outStr)) != ANI_OK) {
        ANS_LOGE("GetStdString failed");
        return status;
    }
    return status;
}

ani_status GetPropertyBool(ani_env *env, ani_object obj, const char *name,
    ani_boolean isUndefined, bool outvalue)
{
    ANS_LOGE("GetPropertyBool start");
    if (env == nullptr || obj == nullptr || name == nullptr) {
        ANS_LOGE("GetPropertyBool fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("GetPropertyBool: %{public}s", name);
    ani_ref refObj = nullptr;
    ani_status status = ANI_ERROR;
    status = env->Object_GetPropertyByName_Ref(obj, name, &refObj);
    if (ANI_OK != status) {
        ANS_LOGE("Object_GetPropertyByName_Ref fail, status: %{public}d", status);
        return status;
    }
    if ((status = env->Reference_IsUndefined(refObj, &isUndefined)) != ANI_OK) {
        ANS_LOGE("Reference_IsUndefined failed, status : %{public}d", status);
        return status;
    }
    if (isUndefined) {
        ANS_LOGE("%{public}s is undefined", name);
        return ANI_INVALID_ARGS;
    }
    ani_boolean result = ANI_FALSE;
    if ((status = env->Object_CallMethodByName_Boolean(static_cast<ani_object>(refObj),
        "unboxed", ":Z", &result)) != ANI_OK) {
        ANS_LOGE("Object_CallMethodByName_Boolean failed, status : %{public}d", status);
        return status;
    }
    outvalue = (result == ANI_TRUE);
    return status;
}

ani_status GetPropertyDouble(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_double &outvalue)
{
    if (env == nullptr || obj == nullptr || name == nullptr) {
        ANS_LOGE("GetPropertyDouble fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("GetPropertyDouble: %{public}s", name);
    ani_status status = ANI_ERROR;
    ani_ref refObj;
    status = GetPropertyRef(env, obj, name, isUndefined, refObj);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("%{public}s is undefined", name);
        return ANI_INVALID_ARGS;
    }
    if ((status = env->Object_CallMethodByName_Double(static_cast<ani_object>(refObj),
        "unboxed", ":D", &outvalue)) != ANI_OK) {
        ANS_LOGE("Object_CallMethodByName_Boolean failed, status : %{public}d", status);
        return status;
    }
    ANS_LOGD("Object_CallMethodByName_Double sucess, status: %{public}f", outvalue);
    return status;
}

ani_status GetPropertyRef(ani_env *env, ani_object obj, const char *name, ani_boolean &isUndefined, ani_ref &outRef)
{
    ANS_LOGD("GetPropertyRef call");
    if (env == nullptr || obj == nullptr || name == nullptr) {
        ANS_LOGE("GetPropertyRef fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("GetPropertyRef: %{public}s", name);
    ani_status status = env->Object_GetPropertyByName_Ref(obj, name, &outRef);
    if (status != ANI_OK) {
        ANS_LOGE("Failed to get property '%{public}s', status: %{public}d", name, status);
        return status;
    }
    if (outRef == nullptr) {
        ANS_LOGE("get Ref fialed, outRef is nullptr");
        return ANI_ERROR;
    }
    status = env->Reference_IsUndefined(outRef, &isUndefined);
    if (status != ANI_OK) {
        ANS_LOGE("Failed to check undefined for '%{public}s', status: %{public}d", name, status);
    }
    ANS_LOGD("GetPropertyRef end");
    return status;
}

ani_status GetPropertyStringArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<std::string> &res)
{
    if (env == nullptr || param == nullptr || name == nullptr) {
        ANS_LOGE("GetPropertyStringArray fail, has nullptr");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("GetPropertyStringArray: %{public}s", name);
    ani_ref arrayObj = nullptr;
    ani_status status;
    ani_double length;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyRef fail, status = %{public}d, isUndefind = %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }
    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return status;
    }
    std::string str = "";
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGE("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        status = GetStringByAniString(env, static_cast<ani_string>(stringEntryRef), str);
        if (status != ANI_OK) {
            ANS_LOGE("GetStdString failed, index: %{public}d", i);
            return status;
        }
        res.push_back(str);
        ANS_LOGD("GetStdString index: %{public}d %{public}s", i, str.c_str());
    }
    return status;
}

ani_object GetAniStringArrayByVectorString(ani_env *env, std::vector<std::string> &strs)
{
    if (env == nullptr || strs.empty()) {
        ANS_LOGE("GetAniStringArrayByVectorString fail, env is nullptr or strs is empty");
        return nullptr;
    }
    int length = strs.size();
    ani_object arrayObj = newArrayClass(env, length);
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size i = 0;
    for (auto &str : strs) {
        ani_string aniStr;
        if ((GetAniStringByString(env, str, aniStr) == ANI_OK)) {
            return nullptr;
        }
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
    if (env == nullptr || cls == nullptr || object == nullptr || fieldName.empty()) {
        ANS_LOGE("SetFieldString fail, has nullptr or fieldName is empty");
        return false;
    }
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    ANS_LOGD("SetFieldString fieldName : %{public}s", fieldName.c_str());
    if (status != ANI_OK || field == nullptr) {
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
    if (env == nullptr || cls == nullptr || object == nullptr || fieldName.empty()) {
        ANS_LOGE("SetOptionalFieldBoolean fail, has nullptr or fieldName is empty");
        return false;
    }
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_object boolObj = CreateBoolean(env, BoolToAniBoolean(value));
    if (boolObj == nullptr) {
        return false;
    }
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
    if (env == nullptr || cls == nullptr || object == nullptr || fieldName.empty()) {
        ANS_LOGE("SetOptionalFieldDouble fail, has nullptr or fieldName is empty");
        return false;
    }
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_object doubleObj = CreateDouble(env, value);
    if (doubleObj == nullptr) {
        return false;
    }
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
    ani_class persion_cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_BOOLEAN, &persion_cls)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persion_cls, "<ctor>", "Z:V", &personInfoCtor)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persion_cls, personInfoCtor, &personInfoObj, value ? ANI_TRUE : ANI_FALSE)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return nullptr;
    }
    return personInfoObj;
}
ani_object CreateDouble(ani_env *env, double value)
{
    if (env == nullptr) {
        ANS_LOGE("CreateDouble fail, env is nullptr");
        return nullptr;
    }
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
    if (env == nullptr || length < 0) {
        ANS_LOGE("CreateDouble fail, env is nullptr or length is less than zero");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)){
        ANS_LOGE("FindClass Lescompat/Array; Failed");
        return nullptr;
    }
    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)){
        ANS_LOGE("Class_FindMethod <ctor> Failed");
        return nullptr;
    }
    ani_object arrayObj = nullptr;
    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, length)){
        ANS_LOGE("Object_New Array Faild");
        return nullptr;
    }
    ANS_LOGD("newArrayClass end");
    return arrayObj;
}

ani_object newRecordClass(ani_env *env)
{
    ANS_LOGD("newRecordClass call");
    if (env == nullptr) {
        ANS_LOGE("newRecordClass fail, env is nullptr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class recordCls;
    if (ANI_OK != (status = env->FindClass("Lescompat/Record;", &recordCls))) {
        ANS_LOGE("newRecordClass fail, FindClass status = %{public}d", status);
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != (status = env->Class_FindMethod(recordCls, "<ctor>", nullptr, &ctor))) {
        ANS_LOGE("newRecordClass fail, Class_FindMethod status = %{public}d", status);
        return nullptr;
    }
    ani_object recordObj = {};
    if (ANI_OK != (status = env->Object_New(recordCls, ctor, &recordObj))) {
        ANS_LOGE("newRecordClass fail, Object_New status = %{public}d", status);
        return nullptr;
    }
    ANS_LOGD("newRecordClass end");
    return recordObj;
}

ani_object ConvertArrayDoubleToAniObj(ani_env *env, const std::vector<std::int64_t> values)
{
    if (env == nullptr || values.empty()) {
        ANS_LOGE("ConvertArrayDoubleToAniObj fail, env is nullptr or values is empty");
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
    if (env == nullptr || cls == nullptr || object == nullptr || fieldName.empty()) {
        ANS_LOGE("SetOptionalFieldArrayDouble fail, has nullptr or fieldName is empty");
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
    if (env == nullptr || className == nullptr) {
        ANS_LOGE("CreateClassObjByClassName fail, has nullptr");
        return false;
    }
    if (ANI_OK != env->FindClass(className, &cls)) {
        return false;
    }
    ani_method ctor;
    ANI_FAILED_AND_RETURN(env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor));
    outAniObj = {};
    ANI_FAILED_AND_RETURN(env->Object_New(cls, ctor, &outAniObj));
    return true;
}

bool CreateDate(ani_env *env, int64_t time, ani_object &outObj)
{
    if (env == nullptr || time < 0) {
        ANS_LOGE("CreateDate fail, env is nullptr or time is invalid value");
        return false;
    }
    ani_class cls;
    ani_status status;
    if (ANI_OK != (status = env->FindClass("Lescompat/Date;", &cls))) {
        ANS_LOGD("error. not find class name 'Lescompat/Date;'. status %{public}d", status);
        return false;
    }
    ani_method ctor;
    if (ANI_OK != (status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/Object;:V", &ctor))) {
        ANS_LOGD("error. not find method name '<ctor>'. status %{public}d", status);
        return false;
    }
    ani_object timeObj = CreateDouble(env, static_cast<double>(time));
    if (timeObj == nullptr) {
        ANS_LOGD("createDouble faild");
        return false;
    }
    if (ANI_OK != (status = env->Object_New(cls, ctor, &outObj, timeObj))) {
        ANS_LOGD("Object_New faild. status %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateInt(ani_env *env, int32_t value)
{
    ani_class cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_INT, &cls)) != ANI_OK) {
        ANS_LOGE("FindClass '%{public}s' faild. status %{public}d", CLASSNAME_INT, status);
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor)) != ANI_OK) {
        ANS_LOGE("Class_FindMethod '%{public}s' faild. status %{public}d", CLASSNAME_INT, status);
        return nullptr;
    }
    ani_object outObj;
    if ((status = env->Object_New(cls, ctor, &outObj, value)) != ANI_OK) {
        ANS_LOGE("Object_New '%{public}s' faild. status %{public}d", CLASSNAME_INT, status);
        return nullptr;
    }
    return outObj;
}

bool SetPropertyOptionalByBoolean(ani_env *env, ani_object object, const char *name, bool value)
{
    ANS_LOGD("enter SetPropertyOptionalByBoolean");
    if (env == nullptr || object == nullptr || name == nullptr) {
        ANS_LOGE("The parameter is invalid.");
        return false;
    }
    ani_ref boolObj = CreateBoolean(env, value);
    if (boolObj == nullptr) {
        ANS_LOGE("CreateBoolean faild");
        return false;
    }
    return SetPropertyByRef(env, object, name, boolObj);
}

bool SetPropertyOptionalByDouble(ani_env *env, ani_object object, const char *name, double value)
{
    ANS_LOGD("enter SetPropertyOptionalByDouble");
    if (env == nullptr || object == nullptr || name == nullptr) {
        ANS_LOGE("The parameter is invalid.");
        return false;
    }
    ani_ref doubleObj = CreateDouble(env, value);
    if (doubleObj == nullptr) {
        ANS_LOGE("CreateDouble faild");
        return false;
    }
    return SetPropertyByRef(env, object, name, doubleObj);
}

bool SetPropertyOptionalByString(ani_env *env, ani_object object, const char *name, const std::string value)
{
    ANS_LOGD("enter SetPropertyOptionalByString");
    if (env == nullptr || object == nullptr || name == nullptr) {
        ANS_LOGE("The parameter is invalid.");
        return false;
    }
    ani_string stringObj;
    ani_status status = ANI_OK;
    if (ANI_OK != (status = GetAniStringByString(env, value, stringObj))) {
        ANS_LOGE("GetAniStringByString faild. status %{public}d", status);
        return false;
    }
    if (stringObj == nullptr) {
        ANS_LOGE("CreateString faild");
        return false;
    }
    return SetPropertyByRef(env, object, name, static_cast<ani_ref>(stringObj));
}

bool SetPropertyOptionalByInt(ani_env *env, ani_object object, const char *name, int32_t value)
{
    ANS_LOGD("enter SetPropertyOptionalByInt");
    if (env == nullptr || object == nullptr || name == nullptr) {
        ANS_LOGE("The parameter is invalid.");
        return false;
    }
    ani_ref IntObj = CreateInt(env, value);
    if (IntObj == nullptr) {
        ANS_LOGE("CreateInt faild");
        return false;
    }
    return SetPropertyByRef(env, object, name, IntObj);
}

bool SetPropertyByRef(ani_env *env, ani_object object, const char *name, ani_ref value)
{
    ANS_LOGD("enter SetPropertyByRef");
    ani_status status = ANI_OK;
    if (env == nullptr || object == nullptr || name == nullptr || value == nullptr) {
        ANS_LOGE("The parameter is invalid.");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(object, name, value))) {
        ANS_LOGE("set '%{public}s' faild. status %{public}d", name, status);
        return false;
    }
    return true;
}

} // namespace NotificationSts
} // OHOS