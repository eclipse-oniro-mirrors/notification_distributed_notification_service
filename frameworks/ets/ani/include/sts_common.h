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
#include <string>
#include <vector>
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
bool IsUndefine(ani_env *env, const ani_object &obj);
ani_object CreateBoolean(ani_env *env, bool value);
ani_object CreateDouble(ani_env *env, ani_double value);
bool CreateDate(ani_env *env, int64_t time, ani_object &outObj);
ani_status GetAniStringByString(ani_env* env, const std::string str, ani_string &aniStr);
ani_status GetStringByAniString(ani_env *env, ani_string str, std::string &res);
bool GetStringArrayByAniObj(ani_env *env, const ani_object ani_obj, std::vector<std::string> &stdVString);
ani_object GetAniStringArrayByVectorString(ani_env *env, std::vector<std::string> &strs);
ani_object newArrayClass(ani_env *env, int length);
ani_object newRecordClass(ani_env *env);
ani_object ConvertArrayDoubleToAniObj(ani_env *env, const std::vector<std::int64_t> values);

ani_status GetPropertyString(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, std::string &outStr);
ani_status GetPropertyBool(ani_env *env, ani_object obj, const char *name,
    ani_boolean isUndefined, bool outvalue);
ani_status GetPropertyDouble(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_double &outvalue);
ani_status GetPropertyRef(ani_env *env, ani_object obj, const char *name,
    ani_boolean &isUndefined, ani_ref &outRef);
ani_status GetPropertyStringArray(ani_env *env, ani_object param, const char *name,
    ani_boolean &isUndefined, std::vector<std::string> &res);

bool SetFieldString(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, const std::string value);
bool SetOptionalFieldBoolean(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, bool value);
bool SetOptionalFieldDouble(ani_env *env, ani_class cls, ani_object &object,
    const std::string fieldName, double value);
bool SetOptionalFieldArrayDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
    const std::vector<std::int64_t> &values);

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
static bool CallSetter(ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
{
    if(env == nullptr || cls == nullptr || object == nullptr) {
        return false;
    }
    std::string setterName("<set>");
    setterName.append(propertyName);
    ani_method setter;
    ani_status status = env->Class_FindMethod(cls, setterName.c_str(), nullptr, &setter);
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

template<typename valueType>
static bool CallSetterOptional(
    ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
{
    if(env == nullptr || cls == nullptr || object == nullptr) {
        return false;
    }
    if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
        return CallSetter(env, cls, object, propertyName, value);
    }
    const char* valueClassName = nullptr;
    const char* ctorSig = nullptr;
    if constexpr (std::is_same_v<valueType, ani_boolean>) {
        valueClassName = "Lstd/core/Boolean;";
        ctorSig = "Z:V";
    } else if constexpr (std::is_same_v<valueType, ani_char>) {
        valueClassName = "Lstd/core/Char;";
        ctorSig = "C:V";
    } else if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                         std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                         std::is_same_v<valueType, ani_long> ||
                         std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
        valueClassName = "Lstd/core/Double;";
        ctorSig = "D:V";
    } else {
        ANS_LOGE("Classname %{public}s Unsupported", propertyName);
        return false;
    }
    ani_class valueClass = nullptr;
    ani_status status = env->FindClass(valueClassName, &valueClass);
    if (status != ANI_OK) {
        ANS_LOGE("FindClass %{public}s %{public}s failed %{public}d", propertyName, valueClassName, status);
        return false;
    }
    ani_method ctor = nullptr;
    status = env->Class_FindMethod(valueClass, "<ctor>", ctorSig, &ctor);
    if (status != ANI_OK) {
        ANS_LOGE("Class_FindMethod <ctor> %{public}s failed %{public}d", propertyName, status);
        return false;
    }
    ani_object valueObj = nullptr;
    if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                  std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                  std::is_same_v<valueType, ani_long> ||
                  std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
        status = env->Object_New(valueClass, ctor, &valueObj, static_cast<double>(value));
    } else {
        ANS_LOGE("Classname %{public}s Unsupported", propertyName);
        return false;
    }
    if (status != ANI_OK) {
        ANS_LOGE("Object_New %{public}s failed %{public}d", propertyName, status);
        return false;
    }
    return CallSetter(env, cls, object, propertyName, valueObj);
}

[[maybe_unused]]static bool CallSetterNull(ani_env* env, ani_class cls, ani_object object, const char* propertyName)
{
    ani_ref nullRef = nullptr;
    ani_status status = env->GetNull(&nullRef);
    if (status != ANI_OK) {
        ANS_LOGE("GetNull %{public}s failed %{public}d", propertyName, status);
        return false;
    }
    return CallSetter(env, cls, object, propertyName, nullRef);
}

template <class T>
static bool EnumConvertAniToNative(ani_env *env, ani_enum_item enumItem, T &result)
{
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
        status = GetStdString(env, strValue, result);
        if (ANI_OK != status) {
            ANS_LOGD("EnumConvertAniToNative GetStdString failed, status : %{public}d", status);
            return false;
        }
    } else {
        ANS_LOGD("Enum convert failed: type not supported");
        return false;
    }
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

#define ANI_FAILED_AND_RETURN(status)                                                    \
do                                                                                       \
{                                                                                        \
    ani_status const local_status = (status);                                            \
    if (ani_status::ANI_OK != local_status)                                              \
    {                                                                                    \
        ANS_LOGE("check status error: %{public}d", (int)local_status); \
        return false;                                                                    \
    }                                                                                    \
} while (0)

#define RETURN_NULL_IF_NULL(ptr)     \
    do {                             \
        if ((ptr) == nullptr) {      \
            ANS_LOGE("ptr is null"); \
            return nullptr;          \
        }                            \
    } while (0)
#define RETURN_FALSE_IF_NULL(ptr)    \
    do {                             \
        if ((ptr) == nullptr) {      \
            ANS_LOGE("ptr is null"); \
            return false;            \
        }                            \
    } while (0)
#define RETURN_NULL_IF_FALSE(condition)     \
    do {                                    \
        if (!(condition)) {                 \
            ANS_LOGE("condition is false"); \
            return nullptr;                 \
        }                                   \
    } while (0)
#define RETURN_FALSE_IF_FALSE(condition)     \
    do {                                     \
        if (!(condition)) {                  \
            return false;                    \
        }                                    \
    } while (0)
#define RETURN_ANI_STATUS_IF_NOT_OK(res, err) \
    do {                                      \
        if ((res) != ANI_OK) {                \
            ANS_LOGE(err);                    \
            return res;                       \
        }                                     \
    } while (0)

} // namespace NotificationSts
} // OHOS
#endif