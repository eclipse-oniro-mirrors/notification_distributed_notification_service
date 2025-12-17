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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_COMMON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_COMMON_H

#include "ani.h"
#include <map>
#include <string>
#include <vector>
#include "ans_log_wrapper.h"
#include <ani_signature_builder.h>

namespace OHOS {
namespace NotificationSts {
using namespace arkts::ani_signature;

constexpr int32_t STR_MAX_SIZE = 202;
constexpr int32_t PROFILE_NAME_SIZE = 202;
constexpr int32_t LONG_STR_MAX_SIZE = 1028;
constexpr int32_t COMMON_TEXT_SIZE = 3074;
constexpr int32_t SHORT_TEXT_SIZE = 1026;
constexpr int32_t LONG_LONG_STR_MAX_SIZE = 25600;
constexpr float MAX_PIXEL_SIZE = 128.0f;
std::string GetResizeStr(std::string instr, int32_t length);
int32_t GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

ani_object GetNullObject(ani_env *env);
bool IsUndefine(ani_env *env, const ani_object &obj);
ani_object CreateBoolean(ani_env *env, bool value);
ani_object CreateDouble(ani_env *env, ani_double value);
ani_object CreateInt(ani_env *env, int32_t value);
ani_object CreateLong(ani_env *env, int64_t value);
bool CreateDate(ani_env *env, int64_t time, ani_object &outObj);
bool GetDateByObject(ani_env *env, ani_object timeObj, int64_t &time);
ani_status GetAniStringByString(ani_env* env, const std::string str, ani_string &aniStr);
ani_status GetStringByAniString(ani_env *env, ani_string str, std::string &res);
bool GetStringArrayByAniObj(ani_env *env, const ani_object ani_obj, std::vector<std::string> &stdVString);
ani_object GetAniStringArrayByVectorString(ani_env *env, std::vector<std::string> strs);
bool GetAniStringArrayByVectorStringV2(ani_env *env, std::vector<std::string> strs, ani_object& aniArray);
ani_array newArrayClass(ani_env *env, int length);
ani_object ConvertArrayDoubleToAniObj(ani_env *env, const std::vector<std::int64_t> values);
void ParseRecord(ani_env *env, ani_object recordRef, std::map<std::string, ani_ref>& recordResult);

ani_status GetPropertyString(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, std::string &outStr);
ani_status GetPropertyBool(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, bool &outvalue);
ani_status GetPropertyDouble(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_double &outvalue);
ani_status GetPropertyValueDouble(ani_env *env, ani_object param, const char *name, double &value);
ani_status GetPropertyInt(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_int &outvalue);
ani_status GetPropertyLong(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_long &outvalue);
ani_status GetPropertyRef(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_ref &outRef);
ani_status GetPropertyStringArray(ani_env *env, ani_object param, const char *name,
    std::vector<std::string> &res, const uint32_t maxLen = 0);
ani_status GetPropertyNumberArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<int64_t> &res, const uint32_t maxLen = 0);
ani_status GetPropertyLongArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<int64_t> &res);
ani_status GetPropertyEnumItemArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<ani_enum_item> &res);
void GetPropertyRefValue(ani_env *env, ani_object obj, const char *name, ani_boolean &isUndefined, ani_ref &outRef);

bool SetFieldString(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, const std::string value);
bool SetFieldInt(ani_env *env, ani_class cls, ani_object &object, const std::string fieldName, const int32_t value);
bool SetFieldLong(ani_env *env, ani_class cls, ani_object &object, const std::string fieldName, const int64_t value);
bool SetOptionalFieldBoolean(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, bool value);
bool SetOptionalFieldDouble(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, double value);
bool SetOptionalFieldArrayLong(ani_env *env, ani_class cls, ani_object &object, const std::string fieldName,
    const std::vector<std::int64_t> values);

// property
bool SetPropertyOptionalByBoolean(ani_env *env, ani_object &object, const char *name, bool value);
bool SetPropertyOptionalByDouble(ani_env *env, ani_object &object, const char *name, double value);
bool SetPropertyValueDouble(ani_env *env, ani_object param, const char *name, double value);
bool SetPropertyOptionalByLong(ani_env *env, ani_object &object, const char *name, int64_t value);
bool SetPropertyOptionalByString(ani_env *env, ani_object &object, const char *name, const std::string value);
bool SetPropertyOptionalByInt(ani_env *env, ani_object &object, const char *name, int32_t value);
bool SetPropertyByRef(ani_env *env, ani_object &object, const char *name, ani_ref value);

bool CreateClassObjByClassName(ani_env *env, const char *className, ani_class &cls, ani_object &outAniObj);

inline bool AniBooleanToBool(ani_boolean value)
{
    return value == ANI_TRUE;
}

inline ani_boolean BoolToAniBoolean(bool value)
{
    return value ? ANI_TRUE : ANI_FALSE;
}

template<typename valueType>
static bool CallSetter(ani_env* env, ani_class cls, ani_object &object, const char* propertyName, valueType value)
{
    if (env == nullptr || cls == nullptr || object == nullptr) {
        return false;
    }
    std::string propName(propertyName);
    ani_method setter;
    ani_status status = env->Class_FindMethod(cls, Builder::BuildSetterName(propName).c_str(), nullptr, &setter);
    if (status != ANI_OK) {
        ANS_LOGE("Class_FindMethod %{public}s failed %{public}d", propertyName, status);
        return false;
    }
    if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                  std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                  std::is_same_v<valueType, ani_long> || std::is_same_v<valueType, int32_t> ||
                  std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
        status = env->Object_CallMethod_Void(object, setter, static_cast<double>(value));
    } else {
        status = env->Object_CallMethod_Void(object, setter, value);
    }
    if (status != ANI_OK) {
        ANS_LOGE("Object_CallMethod_Void %{public}s failed %{public}d", propertyName, status);
        return false;
    }
    return true;
}

template <class T>
static bool EnumConvertAniToNative(ani_env *env, ani_enum_item enumItem, T &result)
{
    if (env == nullptr) {
        ANS_LOGE("env nullptr");
        return false;
    }
    ani_status status = ANI_ERROR;
    if constexpr (std::is_enum<T>::value || std::is_integral<T>::value) {
        ani_int intValue{};
        status = env->EnumItem_GetValue_Int(enumItem, &intValue);
        if (ANI_OK != status) {
            ANS_LOGD("EnumConvert_StsToNative failed, status : %{public}d", status);
            return false;
        }
        result = static_cast<T>(intValue);
        return true;
    } else if constexpr (std::is_same<T, std::string>::value) {
        ani_string strValue{};
        status = env->EnumItem_GetValue_String(enumItem, &strValue);
        if (ANI_OK != status) {
            ANS_LOGD("EnumItem_GetValue_String failed, status : %{public}d", status);
            return false;
        }
        status = GetStringByAniString(env, strValue, result);
        if (ANI_OK != status) {
            ANS_LOGD("EnumConvertAniToNative GetStdString failed, status : %{public}d", status);
            return false;
        }
        return true;
    } else {
        ANS_LOGD("Enum convert failed: type not supported");
        return false;
    }
}

template<class T>
void deletePoint(T &result)
{
    delete result;
    result = nullptr;
}

template<class T>
void deleteVectorWithPoints(std::vector<T> &results)
{
    for (auto result : results) {
        deletePoint(result);
    }
    results.clear();
}

template<class T>
void deleteVectorWithSpPoints(std::vector<std::shared_ptr<T>> &results)
{
    for (auto result : results) {
        result = nullptr;
    }
    results.clear();
}

template<class T>
void deleteVectorWithArraySpPoints(std::map<std::string, std::vector<std::shared_ptr<T>>> &results)
{
    for (auto it = results.begin(); it != results.end(); ++it) {
        auto vt = static_cast<std::vector<std::shared_ptr<T>>>(it -> second);
        for (auto pt : vt) {
            pt = nullptr;
        }
        vt.clear();
    }
    results.clear();
}

template<class T>
static bool EnumConvertAniToNative(ani_env *env, ani_object enumItem, T &result)
{
    return EnumConvertAniToNative<T>(env, static_cast<ani_enum_item>(enumItem), result);
}

template <class T>
static bool EnumConvertNativeToAni(ani_env *env, const char *enumName, const T enumValue, ani_enum_item &result)
{
    ani_enum aniEnum{};
    ani_status status = env->FindEnum(enumName, &aniEnum);
    if (ANI_OK != status) {
        ANS_LOGD("Enum convert FindEnum failed: %{public}s status: %{public}d", enumName, status);
        return false;
    }
    constexpr int32_t loopMaxNum = 1000;
    for (int32_t index = 0U; index < loopMaxNum; index++) {
        ani_enum_item enumItem{};
        status = env->Enum_GetEnumItemByIndex(aniEnum, index, &enumItem);
        if (ANI_OK != status) {
            ANS_LOGD(
                "Enum_GetEnumItemByIndex failed: enumName:%{public}s index:%{public}d, status:%{public}d",
                enumName, index, status);
            return false;
        }
        // compare value
        T tmpValue{};
        if (EnumConvertAniToNative<T>(env, enumItem, tmpValue) && tmpValue == enumValue) {
            result = enumItem;
            return true;
        }
    }
    ANS_LOGD("EnumConvert_NativeToSts failed enumName: %{public}s", enumName);
    return false;
}

} // namespace NotificationSts
} // OHOS
#endif