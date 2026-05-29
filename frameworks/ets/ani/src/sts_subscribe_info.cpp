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
#include "sts_subscribe_info.h"

#include "sts_common.h"
#include "ans_log_wrapper.h"
#include "sts_notification_manager.h"
#include "picture_option.h"

namespace OHOS {
namespace NotificationSts {
bool GetSlotTypes(ani_env *env, ani_object value, NotificationSubscribeInfo &info)
{
    ani_boolean isUndefined = ANI_TRUE;
    std::vector<ani_enum_item> slotTypesEnum = {};
    if (ANI_OK != GetPropertyEnumItemArray(env, value, "slotTypes", isUndefined, slotTypesEnum)) {
        ANS_LOGE("GetPropertyEnumItemArray fail or undefined");
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        return true;
    }
    if (slotTypesEnum.empty()) {
        ANS_LOGE("slotTypes is empty");
        return false;
    }
    std::vector<SlotType> slotTypes = {};
    for (auto slotTypeEnum : slotTypesEnum) {
        SlotType slotType = SlotType::OTHER;
        if (!SlotTypeEtsToC(env, slotTypeEnum, slotType)) {
            ANS_LOGE("SlotTypeEtsToC failed");
            return false;
        }
        slotTypes.push_back(slotType);
    }
    info.SetSlotTypes(slotTypes);
    return true;
}

bool GetVoiceContentOption(ani_env *env, ani_object value, NotificationSubscribeInfo &info)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref voiceContentOptionRef = nullptr;
    ani_status status = GetPropertyRef(env, value, "voiceContentOptions", isUndefined, voiceContentOptionRef);
    if (status != ANI_OK) {
        ANS_LOGE("GetPropertyRefRef voiceContentOption failed");
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        return true;
    }
    ani_boolean enabledUndefined = ANI_TRUE;
    bool enabled = false;
    if (GetPropertyBool(env, static_cast<ani_object>(voiceContentOptionRef), "enabled", enabledUndefined,
        enabled) != ANI_OK || enabledUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyBool enabled failed");
        return false;
    }
    sptr<OHOS::Notification::VoiceContentOption> voiceContentOption =
        new (std::nothrow) OHOS::Notification::VoiceContentOption(enabled);
    if (voiceContentOption != nullptr) {
        info.SetVoiceContentOption(voiceContentOption);
    }
    return true;
}

bool GetPictureOption(ani_env *env, ani_object value, NotificationSubscribeInfo &info)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref pictureOptionRef = nullptr;
    ani_status status = GetPropertyRef(env, value, "pictureOptions", isUndefined, pictureOptionRef);
    if (status != ANI_OK) {
        ANS_LOGE("GetPropertyRef pictureOptions failed");
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        return true;
    }
    std::vector<std::string> picList;
    if (GetPropertyStringArray(env, static_cast<ani_object>(pictureOptionRef),
        "preparseLiveViewPicList", picList) != ANI_OK) {
        ANS_LOGE("GetPropertyStringArray preparseLiveViewPicList failed");
        return false;
    }
    sptr<OHOS::Notification::PictureOption> pictureOption =
        new (std::nothrow) OHOS::Notification::PictureOption(picList);
    if (pictureOption != nullptr) {
        info.SetPictureOption(pictureOption);
    }
    return true;
}

bool UnwarpNotificationSubscribeInfo(ani_env *env, ani_object value, NotificationSubscribeInfo &info)
{
    ANS_LOGD("enter");
    if (env == nullptr || value == nullptr) {
        ANS_LOGE("env or value is null");
        return false;
    }
    std::vector<std::string> res = {};
    ani_int userId = 0;
    ani_long filterLimit = 0;
    std::string deviceType;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK != GetPropertyStringArray(env, value, "bundleNames", res)|| res.empty()) {
        ANS_LOGE("GetPropertyStringArray bundleNames faild");
    }
    std::vector<std::string> bundleNames = {};
    for (auto bundleName : res) {
        bundleNames.emplace_back(GetResizeStr(bundleName, STR_MAX_SIZE));
    }
    if (ANI_OK != GetPropertyInt(env, value, "userId", isUndefined, userId) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyInt userId faild");
    }
    if (ANI_OK != GetPropertyString(env, value, "deviceType", isUndefined, deviceType) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyString deviceType faild");
    }
    if (ANI_OK != GetPropertyLong(env, value, "filterLimit", isUndefined, filterLimit) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetPropertyLong filterLimit faild");
    }
    if (!GetSlotTypes(env, value, info)) {
        ANS_LOGE("GetSlotTypes faild");
        return false;
    }
    info.AddAppNames(bundleNames);
    info.AddAppUserId(userId);
    info.SetFilterType(static_cast<uint32_t>(filterLimit));
    info.AddDeviceType(GetResizeStr(deviceType, STR_MAX_SIZE));
    if (!GetVoiceContentOption(env, value, info)) {
        return false;
    }
    if (!GetPictureOption(env, value, info)) {
        return false;
    }
    ANS_LOGD("userId %{public}d deviceType %{public}s filterLimit %{public}d voiceContentOption %{public}s",
        info.GetAppUserId(), info.GetDeviceType().c_str(), info.GetFilterType(),
        info.GetVoiceContentOption() != nullptr ? "enabled" : "null");
    return true;
}

} // namespace NotificationSts
} // OHOS
