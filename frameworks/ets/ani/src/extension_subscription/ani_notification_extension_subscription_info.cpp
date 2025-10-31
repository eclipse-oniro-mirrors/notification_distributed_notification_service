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
#include "ani_notification_extension_subscription_info.h"

#include "sts_common.h"
#include "sts_notification_manager.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
namespace {
constexpr const char* NOTIFICATION_EXTENSION_SUBSCRIPTION_INFO_CLASSNAME =
    "notification.NotificationExtensionSubscriptionInfo.NotificationExtensionSubscriptionInfoInner";
constexpr const char* NOTIFICATION_EXTENSION_SUBSCRIPTION_SUBSCRIBE_TYPE_CLASSNAME =
    "@ohos.notificationExtensionSubscription.notificationExtensionSubscription.SubscribeType";
}

bool SubscribeTypeCToSts(const NotificationConstant::SubscribeType inType, STSSubscribeType& outType)
{
    switch (inType) {
        case NotificationConstant::SubscribeType::BLUETOOTH:
            outType = STSSubscribeType::BLUETOOTH;
            break;
        default:
            ANS_LOGE("SubscribeType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool SubscribeTypeCToSts(ani_env *env, const NotificationConstant::SubscribeType inType, ani_enum_item &enumItem)
{
    ANS_LOGD("SubscribeTypeCToSts call");
    STSSubscribeType outType;
    if (!SubscribeTypeCToSts(inType, outType) ||
        !EnumConvertNativeToAni(env, NOTIFICATION_EXTENSION_SUBSCRIPTION_SUBSCRIBE_TYPE_CLASSNAME, outType, enumItem)) {
        ANS_LOGE("SubscribeTypeCToSts failed");
        return false;
    }
    return true;
}

bool SubscribeTypeStsToC(const STSSubscribeType inType, NotificationConstant::SubscribeType& outType)
{
    switch (inType) {
        case STSSubscribeType::BLUETOOTH:
            outType = NotificationConstant::SubscribeType::BLUETOOTH;
            break;
        default:
            ANS_LOGE("STSSubscribeType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

ani_status UnwarpNotificationExtensionSubscribeInfo(
    ani_env *env, ani_object value, sptr<NotificationExtensionSubscriptionInfo> &info)
{
    ANS_LOGD("UnwarpNotificationExtensionSubscribeInfo call");
    if (env == nullptr || value == nullptr) {
        ANS_LOGE("env or value is null");
        return ANI_ERROR;
    }

    ani_status status = ANI_ERROR;
    std::string addr;
    ani_ref type = nullptr;
    ani_boolean isUndefined = ANI_TRUE;

    isUndefined = ANI_TRUE;
    if ((status = GetPropertyString(env, value, "addr", isUndefined, addr)) != ANI_OK) {
        ANS_LOGE("GetPropertyString addr failed, status: %{public}d, isUndefined: %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }
    info->SetAddr(GetResizeStr(addr, STR_MAX_SIZE));

    if ((status = GetPropertyRef(env, value, "type", isUndefined, type)) != ANI_OK) {
        ANS_LOGE("GetPropertyRef type failed, status: %{public}d, isUndefined: %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }
    ani_int typeValue {};
    if ((status = env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(type), &typeValue)) != ANI_OK) {
        ANS_LOGE("EnumItem_GetValue_Int type failed, status: %{public}d, isUndefined: %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }
    NotificationConstant::SubscribeType typeEnum;
    if (!SubscribeTypeStsToC(static_cast<STSSubscribeType>(typeValue), typeEnum)) {
        ANS_LOGE("SubscribeTypeStsToC failed");
        return ANI_INVALID_ARGS;
    }
    info->SetType(typeEnum);

    ANS_LOGD("UnwarpNotificationExtensionSubscribeInfo success - addr: %{public}s, type: %{public}d",
        info->GetAddr().c_str(), static_cast<int>(info->GetType()));
    
    return status;
}

ani_status UnwarpNotificationExtensionSubscribeInfoArrayByAniObj(ani_env *env, ani_object arrayValue,
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> &infos)
{
    ANS_LOGD("UnwarpNotificationExtensionSubscribeInfoArrayByAniObj enter");
    if (arrayValue == nullptr) {
        ANS_LOGE("arrayValue is null");
        return ANI_ERROR;
    }
    infos.clear();
    ani_size size = 0;
    ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(arrayValue), &size);
    if (status != ANI_OK) {
        ANS_LOGE("Array_GetLength failed. status : %{public}d", status);
        return status;
    }
    ani_ref ref;
    for (ani_size i = 0; i < size; i++) {
        status = env->Array_Get_Ref(reinterpret_cast<ani_array_ref>(arrayValue), i, &ref);
        if (status != ANI_OK) {
            ANS_LOGE("Array_Get_Ref failed. status : %{public}d", status);
            return status;
        }
        sptr<NotificationExtensionSubscriptionInfo> info = new (std::nothrow)NotificationExtensionSubscriptionInfo();
        if (info == nullptr) {
            ANS_LOGE("Create NotificationExtensionSubscriptionInfo failed");
            return ANI_ERROR;
        }
        status = UnwarpNotificationExtensionSubscribeInfo(env, static_cast<ani_object>(ref), info);
        if (status != ANI_OK) {
            ANS_LOGE("UnwarpNotificationExtensionSubscribeInfo failed. status : %{public}d", status);
            return status;
        }
        infos.emplace_back(info);
    }
    ANS_LOGD("UnwarpNotificationExtensionSubscribeInfoArrayByAniObj leave");
    return ANI_OK;
}

bool WrapNotificationExtensionSubscribeInfo(
    ani_env* env, sptr<Notification::NotificationExtensionSubscriptionInfo> info, ani_object& outAniObj)
{
    ANS_LOGD("WrapNotificationExtensionSubscribeInfo call");
    if (env == nullptr || info == nullptr) {
        ANS_LOGE("WrapNotificationExtensionSubscribeInfo failed, has nullptr");
        return false;
    }
    ani_class cls;
    if (!CreateClassObjByClassName(env, NOTIFICATION_EXTENSION_SUBSCRIPTION_INFO_CLASSNAME, cls, outAniObj)) {
        ANS_LOGE("WrapNotificationExtensionSubscribeInfo: CreateClassObjByClassName fail");
        return false;
    }
    if (cls == nullptr || outAniObj == nullptr) {
        ANS_LOGE("Create class failed");
        return false;
    }

    if (!SetPropertyOptionalByString(env, outAniObj, "addr", info->GetAddr())) {
        ANS_LOGE("Set addr fail");
        return false;
    }
    ani_enum_item typeEnum {};
    if (!SubscribeTypeCToSts(env, info->GetType(), typeEnum) ||
        !SetPropertyByRef(env, outAniObj, "type", typeEnum)) {
        ANS_LOGE("Set type fail");
        return false;
    }
    ANS_LOGD("WrapNotificationExtensionSubscribeInfo end");
    return true;
}

bool WrapNotificationExtensionSubscribeInfoArray(ani_env* env,
    const std::vector<sptr<Notification::NotificationExtensionSubscriptionInfo>>& infos, ani_object& outAniObj)
{
    ANS_LOGD("WrapNotificationExtensionSubscribeInfo call");
    if (env == nullptr) {
        ANS_LOGE("WrapNotificationExtensionSubscribeInfo failed, has nullptr");
        return false;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(NOTIFICATION_EXTENSION_SUBSCRIPTION_INFO_CLASSNAME, &cls);
    if (status != ANI_OK) {
        ANS_LOGE("FindClass failed. status : %{public}d", status);
        return false;
    }
    ani_array_ref array = nullptr;
    size_t size = infos.size();
    status = env->Array_New_Ref(cls, size, nullptr, &array);
    if (status != ANI_OK) {
        ANS_LOGE("Array_New_Ref failed. status : %{public}d", status);
        return false;
    }
    int32_t index = 0;
    for (auto &it : infos) {
        ani_object infoObj;
        if (!WrapNotificationExtensionSubscribeInfo(env, it, infoObj) || infoObj == nullptr) {
            ANS_LOGE("WrapNotificationExtensionSubscribeInfo Failed. index = %{public}d", index);
            return false;
        }
        status = env->Array_Set_Ref(array, index, infoObj);
        if (status != ANI_OK) {
            ANS_LOGE("Array_Set_Ref Failed. index = %{public}d, status = %{public}d", index, status);
            return false;
        }
        index++;
    }
    ANS_LOGD("WrapNotificationExtensionSubscribeInfo end");
    outAniObj = array;
    return true;
}
}
}