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
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationSts {
constexpr const char *BUSINESS_ERROR_CLASS = "L@ohos/base/BusinessError;";
constexpr const char *ERROR_CLASS_NAME = "Lescompat/Error;";

int32_t GetExternalCode(const uint32_t errCode)
{
    int32_t externalCode = ERROR_INTERNAL_ERROR;
    switch (errCode) {
        case ERROR_PERMISSION_DENIED:
        case ERROR_NOT_SYSTEM_APP:
        case ERROR_PARAM_INVALID:
        case ERROR_SYSTEM_CAP_ERROR:
        case ERROR_INTERNAL_ERROR:
        case ERROR_DIALOG_IS_POPPING:
        case ERROR_NO_MEMORY:
            externalCode = static_cast<int32_t>(errCode);
            break;
        default:
            externalCode = ErrorToExternal(errCode);
            break;
    }
    return externalCode;
}

void ThrowError(ani_env *env, ani_object err)
{
    if (env == nullptr) {
        ANS_LOGE("null env");
        return;
    }
    env->ThrowError(static_cast<ani_error>(err));
}

void ThrowError(ani_env *env, int32_t errCode, const std::string &errorMsg)
{
    if (env == nullptr) {
        ANS_LOGE("null env");
        return;
    }
    ThrowError(env, CreateError(env, errCode, errorMsg));
}

ani_object WrapError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        ANS_LOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        ANS_LOGE("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }
    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        ANS_LOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(ERROR_CLASS_NAME, &cls)) != ANI_OK) {
        ANS_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        ANS_LOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        ANS_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object CreateError(ani_env *env, ani_int code, const std::string &msg)
{
    if (env == nullptr) {
        ANS_LOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(BUSINESS_ERROR_CLASS, &cls)) != ANI_OK) {
        ANS_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "ILescompat/Error;:V", &method)) != ANI_OK) {
        ANS_LOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, msg);
    if (error == nullptr) {
        ANS_LOGE("error nulll");
        return nullptr;
    }
    ani_object obj = nullptr;
    ani_int iCode(code);
    if ((status = env->Object_New(cls, method, &obj, iCode, error)) != ANI_OK) {
        ANS_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}
}
}