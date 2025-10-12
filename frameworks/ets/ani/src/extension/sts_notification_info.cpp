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
#include "sts_notification_info.h"

#include "sts_common.h"
#include "sts_notification_extension_content.h"
#include "sts_notification_manager.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {

bool SetOptionalFieldSlotType(
    ani_env *env, const ani_class cls, ani_object &object, const std::string fieldName, const SlotType value)
{
    ANS_LOGD("SetOptionalFieldSlotType call");
    if (env == nullptr || cls == nullptr || object == nullptr) {
        ANS_LOGE("SetOptionalFieldSlotType failed, has nullptr");
        return false;
    }
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        ANS_LOGE("Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_enum_item enumItem = nullptr;
    NotificationSts::SlotTypeCToEts(env, value, enumItem);
    if (enumItem == nullptr) {
        ANS_LOGE("null enumItem");
        return false;
    }
    status = env->Object_SetField_Ref(object, field, enumItem);
    if (status != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}

bool SetNotificationInfoByRequiredParameter(
    ani_env *env, ani_class infoCls, ani_object &infoObject,
    const std::shared_ptr<NotificationInfo> &notificationInfo)
{
    ANS_LOGD("SetNotificationInfoParameter call");
    if (env == nullptr || infoCls == nullptr || infoObject == nullptr || notificationInfo == nullptr) {
        ANS_LOGE("SetNotificationInfoParameter fail, has nullptr");
        return false;
    }
    // hashCode: string;
    if (!SetPropertyOptionalByString(env, infoObject, "hashCode", notificationInfo->GetHashCode())) {
        ANS_LOGE("SetNotificationInfoParameter: Set hashCode failed");
        return false;
    }

    // notificationSlotType: notificationManager.SlotType;
    if (!SetOptionalFieldSlotType(
        env, infoCls, infoObject, "notificationSlotType", notificationInfo->GetNotificationSlotType())) {
        ANS_LOGE("SetNotificationInfoParameter: Set notificationSlotType failed");
        return false;
    }

    // content: NotificationExtensionContent;
    ani_object contentObj = WrapNotificationExtensionContent(env, notificationInfo->GetNotificationExtensionContent());
    if (contentObj == nullptr|| !SetPropertyByRef(env, infoObject, "content", contentObj)) {
        ANS_LOGE("SetNotificationInfoParameter: Set content failed");
        return false;
    }

    // bundleName: string;
    if (!SetPropertyOptionalByString(env, infoObject, "bundleName", notificationInfo->GetBundleName())) {
        ANS_LOGD("SetNotificationInfoParameter: Set bundleName failed");
    }

    // appName?: string;
    if (!SetPropertyOptionalByString(env, infoObject, "appName", notificationInfo->GetAppName())) {
        ANS_LOGD("SetNotificationInfoParameter: Set appName failed");
    }

    // deliveryTime?: long;
    if (!SetPropertyOptionalByLong(env, infoObject, "deliveryTime", notificationInfo->GetDeliveryTime())) {
        ANS_LOGD("SetNotificationInfoParameter: Set time failed");
    }

    // groupName?: string;
    if (!SetPropertyOptionalByString(env, infoObject, "groupName", notificationInfo->GetGroupName())) {
        ANS_LOGD("SetNotificationInfoParameter: Set groupName failed");
    }

    ANS_LOGD("SetNotificationInfoParameter end");
    return true;
}

ani_object WrapNotificationInfo(ani_env* env,
    const std::shared_ptr<NotificationInfo> &notificationInfo)
{
    ANS_LOGD("WrapNotificationInfo call");
    if (env == nullptr || notificationInfo == nullptr) {
        ANS_LOGE("WrapNotificationInfo failed, has nullptr");
        return nullptr;
    }
    ani_object infoObject = nullptr;
    ani_class infoCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "Lnotification/notificationInfo/NotificationInfoInner;", infoCls, infoObject)) {
        ANS_LOGE("WrapNotificationInfo : CreateClassObjByClassName failed");
        return nullptr;
    }
    if (!SetNotificationInfoByRequiredParameter(env, infoCls, infoObject, notificationInfo)) {
        ANS_LOGE("WrapNotificationInfo : SetNotificationInfoParameter failed");
        return nullptr;
    }

    return infoObject;
}
}
}