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
    ani_int typeValue = 0;
    ani_boolean isUndefined = ANI_TRUE;

    isUndefined = ANI_TRUE;
    if ((status = GetPropertyString(env, value, "addr", isUndefined, addr)) != ANI_OK) {
        ANS_LOGE("GetPropertyString addr failed, status: %{public}d, isUndefined: %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }

    if ((status = GetPropertyInt(env, value, "type", isUndefined, typeValue)) != ANI_OK) {
        ANS_LOGE("GetPropertyInt type failed, status: %{public}d, isUndefined: %{public}d", status, isUndefined);
        return ANI_INVALID_ARGS;
    }

    info->SetAddr(GetResizeStr(addr, STR_MAX_SIZE));
    info->SetType(static_cast<NotificationConstant::SubscribeType>(typeValue));

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
    ani_int length;
    ani_status status = env->Object_GetPropertyByName_Int(arrayValue, "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("Object_GetPropertyByName_Int faild. status : %{public}d", status);
        return status;
    }
    for (int32_t i = 0; i < length; i++) {
        ani_ref notificationExtensionSubscribeInfoEntryRef;
        status = env->Object_CallMethodByName_Ref(arrayValue,
            "$_get", "i:C{std.core.Object}", &notificationExtensionSubscribeInfoEntryRef, i);
        if (status != ANI_OK) {
            ANS_LOGE("Object_CallMethodByName_Ref faild. status : %{public}d", status);
        }
        sptr<NotificationExtensionSubscriptionInfo> info = new (std::nothrow)NotificationExtensionSubscriptionInfo();
        if (info == nullptr || !UnwarpNotificationExtensionSubscribeInfo(
            env, static_cast<ani_object>(notificationExtensionSubscribeInfoEntryRef), info)) {
            ANS_LOGE("UnwarpNotificationExtensionSubscribeInfoArrayByAniObj faild");
            return ANI_ERROR;
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
        ANS_LOGE("CreateClassObjByClassName fail");
        return false;
    }
    if (cls == nullptr || outAniObj == nullptr) {
        ANS_LOGE("Create class failed");
        return false;
    }

    if (!SetFieldString(env, cls, outAniObj, "addr", info->GetAddr())) {
        ANS_LOGE("Set addr fail");
        return false;
    }
    if (!SetFieldInt(env, cls, outAniObj, "type", static_cast<int32_t>(info->GetType()))) {
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
    if (env == nullptr || infos.empty()) {
        ANS_LOGE("WrapNotificationExtensionSubscribeInfo failed, has nullptr or infos is empty");
        return false;
    }
    outAniObj = newArrayClass(env, infos.size());
    if (outAniObj == nullptr) {
        ANS_LOGE("outAniObj is null, newArrayClass Faild");
        return false;
    }
    int32_t index = 0;
    for (auto &it : infos) {
        ani_object infoObj;
        if (!WrapNotificationExtensionSubscribeInfo(env, it, infoObj) || infoObj == nullptr) {
            ANS_LOGE("WrapNotificationExtensionSubscribeInfo Faild. index = %{public}d", index);
            return false;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(outAniObj, "$_set", "iC{std.core.Object}:", index, infoObj)) {
            ANS_LOGE("set Faild. index = %{public}d", index);
            return false;
        }
        index++;
    }
    ANS_LOGD("WrapNotificationExtensionSubscribeInfo end");
    return true;
}
}
}