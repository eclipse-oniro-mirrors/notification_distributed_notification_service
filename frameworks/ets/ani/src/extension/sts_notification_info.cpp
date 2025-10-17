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

bool SetNotificationInfoByRequiredParameter(
    ani_env* env, ani_object& infoObject, const std::shared_ptr<NotificationInfo>& notificationInfo)
{
    ANS_LOGD("SetNotificationInfoParameter call");
    if (env == nullptr || infoObject == nullptr || notificationInfo == nullptr) {
        ANS_LOGE("SetNotificationInfoParameter fail, has nullptr");
        return false;
    }

    if (!SetPropertyOptionalByString(env, infoObject, "hashCode", notificationInfo->GetHashCode())) {
        ANS_LOGE("SetNotificationInfoParameter: Set hashCode failed");
        return false;
    }

    ani_enum_item slotTypeItem {};
    if (!SlotTypeCToEts(env, notificationInfo->GetNotificationSlotType(), slotTypeItem)) {
        ANS_LOGE("SetNotificationInfoParameter: Set notificationSlotType failed");
        return false;
    }
    SetPropertyByRef(env, infoObject, "notificationSlotType", slotTypeItem);

    ani_object contentObj = WrapNotificationExtensionContent(env, notificationInfo->GetNotificationExtensionContent());
    if (contentObj == nullptr|| !SetPropertyByRef(env, infoObject, "content", contentObj)) {
        ANS_LOGE("SetNotificationInfoParameter: Set content failed");
        return false;
    }

    if (!SetPropertyOptionalByString(env, infoObject, "bundleName", notificationInfo->GetBundleName())) {
        ANS_LOGE("SetNotificationInfoParameter: Set bundleName failed");
    }

    if (!SetPropertyOptionalByString(env, infoObject, "appName", notificationInfo->GetAppName())) {
        ANS_LOGE("SetNotificationInfoParameter: Set appName failed");
    }

    if (!SetPropertyOptionalByLong(env, infoObject, "deliveryTime", notificationInfo->GetDeliveryTime())) {
        ANS_LOGE("SetNotificationInfoParameter: Set time failed");
    }

    if (!SetPropertyOptionalByString(env, infoObject, "groupName", notificationInfo->GetGroupName())) {
        ANS_LOGE("SetNotificationInfoParameter: Set groupName failed");
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
        "notification.NotificationInfo.NotificationInfoInner", infoCls, infoObject)) {
        ANS_LOGE("WrapNotificationInfo : CreateClassObjByClassName failed");
        return nullptr;
    }
    if (!SetNotificationInfoByRequiredParameter(env, infoObject, notificationInfo)) {
        ANS_LOGE("WrapNotificationInfo : SetNotificationInfoParameter failed");
        return nullptr;
    }

    return infoObject;
}
}
}