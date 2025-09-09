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
#include "sts_notification_content.h"

#include "sts_common.h"
#include "sts_convert_other.h"
#include "want_params.h"
#include "ani_common_want.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using NotificationBasicContent = OHOS::Notification::NotificationBasicContent;

bool StsLiveViewStatusUtils::StsToC(const STSLiveViewStatus inType, LiveViewStatus &outType)
{
    ANS_LOGD("StsLiveViewStatusUtils::StsToC inType = %{public}d", static_cast<int>(inType));
    switch (inType) {
        case STSLiveViewStatus::LIVE_VIEW_CREATE:
            outType = LiveViewStatus::LIVE_VIEW_CREATE;
            break;
        case STSLiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
            outType = LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
            break;
        case STSLiveViewStatus::LIVE_VIEW_END:
            outType = LiveViewStatus::LIVE_VIEW_END;
            break;
        case STSLiveViewStatus::LIVE_VIEW_FULL_UPDATE:
            outType = LiveViewStatus::LIVE_VIEW_FULL_UPDATE;
            break;
        default:
            ANS_LOGE("LiveViewStatus %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsLiveViewStatusUtils::CToSts(const LiveViewStatus inType, STSLiveViewStatus &outType)
{
    ANS_LOGD("StsLiveViewStatusUtils::CToSts:inType = %{public}d", static_cast<int>(inType));
    switch (inType) {
        case LiveViewStatus::LIVE_VIEW_CREATE:
            outType = STSLiveViewStatus::LIVE_VIEW_CREATE;
            break;
        case LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
            outType = STSLiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
            break;
        case LiveViewStatus::LIVE_VIEW_END:
            outType = STSLiveViewStatus::LIVE_VIEW_END;
            break;
        case LiveViewStatus::LIVE_VIEW_FULL_UPDATE:
            outType = STSLiveViewStatus::LIVE_VIEW_FULL_UPDATE;
            break;
        default:
            ANS_LOGE("LiveViewStatus %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool LiveViewStatusEtsToC(ani_env *env, ani_enum_item enumItem, LiveViewStatus &liveViewStatus)
{
    ANS_LOGD("LiveViewStatusEtsToC call");
    if (env == nullptr) {
        ANS_LOGE("LiveViewStatusEtsToC failed, env is nullptr");
        return false;
    }
    STSLiveViewStatus stsLiveViewStatus = STSLiveViewStatus::LIVE_VIEW_CREATE;
    if (!EnumConvertAniToNative(env, enumItem, stsLiveViewStatus)
        || !StsLiveViewStatusUtils::StsToC(stsLiveViewStatus, liveViewStatus)) {
        ANS_LOGE("LiveViewStatusEtsToC failed");
        return false;
    }
    ANS_LOGD("LiveViewStatusEtsToC end");
    return true;
}

bool LiveViewStatusCToEts(ani_env *env, LiveViewStatus liveViewStatus, ani_enum_item &enumItem)
{
    ANS_LOGD("LiveViewStatusCToEts call");
    if (env == nullptr) {
        ANS_LOGE("LiveViewStatusCToEts failed, env is nullptr");
        return false;
    }
    STSLiveViewStatus stsLiveViewStatus = STSLiveViewStatus::LIVE_VIEW_CREATE;
    if (!StsLiveViewStatusUtils::CToSts(liveViewStatus, stsLiveViewStatus)
        || !EnumConvertNativeToAni(env,
        "notification.notificationContent.#LiveViewStatus", stsLiveViewStatus, enumItem)) {
        ANS_LOGE("LiveViewStatusCToEts failed");
        return false;
    }
    ANS_LOGD("LiveViewStatusCToEts end");
    return true;
}

bool LiveViewTypesEtsToC(ani_env *env, ani_enum_item enumItem, LiveViewTypes &liveViewTypes)
{
    ANS_LOGD("LiveViewTypesEtsToC call");
    return EnumConvertAniToNative(env, enumItem, liveViewTypes);
}

bool LiveViewTypesCToEts(ani_env *env, LiveViewTypes liveViewTypes, ani_enum_item &enumItem)
{
    ANS_LOGD("LiveViewTypesCToEts call");
    return EnumConvertNativeToAni(env,
        "notification.notificationContent.#LiveViewTypes", liveViewTypes, enumItem);
}

void UnWarpNotificationProgress(ani_env *env, ani_object obj, NotificationProgress &notificationProgress)
{
    ANS_LOGD("UnWarpNotificationProgress call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationProgress failed, has nullptr");
        return;
    }
    ani_int maxValueAni = 0;
    ani_boolean isUndefined = ANI_TRUE;
    if (GetPropertyInt(env, obj, "maxValue", isUndefined, maxValueAni) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetMaxValue(maxValueAni);
    } else {
        ANS_LOGD("UnWarpNotificationProgress: get maxValue failed");
    }
    ani_int currentValueAni = 0;
    if (GetPropertyInt(env, obj, "currentValue", isUndefined, currentValueAni) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetCurrentValue(currentValueAni);
    } else {
        ANS_LOGD("UnWarpNotificationProgress: get currentValue failed");
    }
    bool isPercentage = true;
    if (ANI_OK == GetPropertyBool(env, obj, "isPercentage", isUndefined, isPercentage)
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetIsPercentage(isPercentage);
    } else {
        ANS_LOGD("UnWarpNotificationProgress: get isPercentage failed");
    }
    ANS_LOGD("UnWarpNotificationProgress end");
}

bool WarpNotificationProgress(ani_env *env, const NotificationProgress &progress, ani_object &progressObject)
{
    ANS_LOGD("WarpNotificationProgress call");
    if (env == nullptr) {
        ANS_LOGE("WarpNotificationProgress failed, env is nullptr");
        return false;
    }
    ani_class progressClass = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationProgressInner", progressClass, progressObject)
        || progressObject == nullptr) {
        ANS_LOGE("WarpNotificationProgress: create class failed");
        return false;
    }
    // maxValue?: int;
    if (!SetPropertyOptionalByInt(env, progressObject, "maxValue", progress.GetMaxValue())) {
        ANS_LOGD("WarpNotificationProgress: set maxValue failed");
    }
    // currentValue?: int;
    if (!SetPropertyOptionalByInt(env, progressObject, "currentValue", progress.GetCurrentValue())) {
        ANS_LOGD("WarpNotificationProgress: set currentValue failed");
    }
    // isPercentage?: boolean;
    if (!SetPropertyOptionalByBoolean(env, progressObject, "isPercentage", progress.GetIsPercentage())) {
        ANS_LOGD("WarpNotificationProgress: set currentValue failed");
    }
    ANS_LOGD("WarpNotificationProgress end");
    return true;
}

void UnWarpNotificationTime(ani_env *env, ani_object obj,
    NotificationTime &notificationTime)
{
    ANS_LOGD("UnWarpNotificationTime call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationTime failed, has nullptr");
        return;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_int initialTime = 0;
    if (GetPropertyInt(env, obj, "initialTime", isUndefined, initialTime) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationTime.SetInitialTime(initialTime);
    } else {
        ANS_LOGD("UnWarpNotificationTime: get initialTime failed");
    }
    bool isCountDown = true;
    if (ANI_OK == GetPropertyBool(env, obj, "isCountDown", isUndefined, isCountDown)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsCountDown(isCountDown);
    } else {
        ANS_LOGD("UnWarpNotificationTime: get isCountDown failed");
    }
    bool isPaused = true;
    if (ANI_OK == GetPropertyBool(env, obj, "isPaused", isUndefined, isPaused)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsPaused(isPaused);
    } else {
        ANS_LOGD("UnWarpNotificationTime: get isPaused failed");
    }
    bool isInTitle = true;
    isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyBool(env, obj, "isInTitle", isUndefined, isInTitle)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsInTitle(isInTitle);
    } else {
        ANS_LOGD("UnWarpNotificationTime: get isInTitle failed");
    }
    ANS_LOGD("UnWarpNotificationTime end");
}

bool WarpNotificationTime(ani_env *env, const NotificationTime &time, bool isInitialTimeExist, ani_object &timeObject)
{
    ANS_LOGD("WarpNotificationTime call");
    if (env == nullptr) {
        ANS_LOGE("WarpNotificationTime failed, env is nullptr");
        return false;
    }
    ani_class timeClass = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationTimeInner", timeClass, timeObject)
        || timeObject == nullptr) {
        ANS_LOGE("WarpNotificationTime: create class failed");
        return false;
    }
    // initialTime?: int;
    if (isInitialTimeExist) {
        if (!SetPropertyOptionalByInt(env, timeObject, "initialTime", time.GetInitialTime())) {
            ANS_LOGD("WarpNotificationTime: set initialTime failed");
        }
    }
    // isCountDown?: boolean;
    if (!SetPropertyOptionalByBoolean(env, timeObject, "isCountDown", time.GetIsCountDown())) {
        ANS_LOGD("WarpNotificationTime: set isCountDown failed");
    }
    // isPaused?: boolean;
    if (!SetPropertyOptionalByBoolean(env, timeObject, "isPaused", time.GetIsPaused())) {
        ANS_LOGD("WarpNotificationTime: set isPaused failed");
    }
    // isInTitle?: boolean;
    if (!SetPropertyOptionalByBoolean(env, timeObject, "isInTitle", time.GetIsInTitle())) {
        ANS_LOGD("WarpNotificationTime: set isInTitle failed");
    }
    ANS_LOGD("WarpNotificationTime end");
    return true;
}

ani_status UnWarpNotificationIconButton(ani_env *env, ani_object obj, NotificationIconButton &iconButton)
{
    ANS_LOGD("UnWarpNotificationIconButton call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationIconButton failed, env is nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    std::string tempStr = "";
    if ((status = GetPropertyString(env, obj, "name", isUndefined, tempStr)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationIconButton: get name failed, status = %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    std::string name = GetResizeStr(tempStr, STR_MAX_SIZE);
    iconButton.SetName(name);
    ani_ref iconRef = {};
    if ((status = GetPropertyRef(env, obj, "iconResource", isUndefined, iconRef)) != ANI_OK
        || isUndefined == ANI_TRUE || iconRef == nullptr) {
        ANS_LOGE("UnWarpNotificationIconButton: get iconResource failed, status = %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    ResourceManager::Resource resource;
    if (ANI_OK == UnwrapResource(env, static_cast<ani_object>(iconRef), resource)) {
        iconButton.SetIconResource(std::make_shared<ResourceManager::Resource>(resource));
    } else {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(iconRef));
        if (pixelMap == nullptr) {
            ANS_LOGE("UnWarpNotificationIconButton: get iconResource failed");
            return ANI_INVALID_ARGS;
        }
        iconButton.SetIconImage(pixelMap);
    }
    if (GetPropertyString(env, obj, "text", isUndefined, tempStr) == ANI_OK && isUndefined == ANI_FALSE) {
        std::string text = GetResizeStr(tempStr, STR_MAX_SIZE);
        iconButton.SetText(text);
    } else {
        ANS_LOGD("UnWarpNotificationIconButton: get text failed");
    }
    bool hidePanel = true;
    if (ANI_OK == GetPropertyBool(env, obj, "hidePanel", isUndefined, hidePanel)
        && isUndefined == ANI_FALSE) {
        iconButton.SetHidePanel(hidePanel);
    } else {
        ANS_LOGD("UnWarpNotificationIconButton: get hidePanel failed");
    }
    ANS_LOGD("UnWarpNotificationIconButton end");
    return status;
}

ani_status GetIconButtonArray(ani_env *env, ani_object param, const char *name,
    std::vector<NotificationIconButton> &res, const uint32_t maxLen)
{
    ANS_LOGD("GetIconButtonArray call");
    if (env == nullptr || param == nullptr || name == nullptr) {
        ANS_LOGE("GetIconButtonArray failed, has nullptr");
        return ANI_ERROR;
    }
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_int length;
    if (((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK)) {
        ANS_LOGE("get param failed, may be %{public}s : undefined", name);
        return ANI_INVALID_ARGS;
    }
    if (isUndefined == ANI_TRUE) {
        return ANI_OK;
    }
    status = env->Object_GetPropertyByName_Int(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
        return status;
    }
    if (length > maxLen) {
        length = static_cast<ani_int>(maxLen);
    }
    for (int32_t i = 0; i < length; i++) {
        ani_ref buttonRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "i:C{std.core.Object}", &buttonRef, i);
        if (status != ANI_OK) {
            ANS_LOGE("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        NotificationIconButton button;
        if (UnWarpNotificationIconButton(env, static_cast<ani_object>(buttonRef), button) == ANI_OK) {
            res.push_back(button);
        } else {
            ANS_LOGE("GetIconButtonArray: UnWarpNotificationIconButton failed");
            return ANI_INVALID_ARGS;
        }
    }
    ANS_LOGD("GetIconButtonArray end");
    return status;
}

void UnWarpNotificationLocalLiveViewButton(ani_env *env, ani_object obj,
    NotificationLocalLiveViewButton &button)
{
    ANS_LOGD("UnWarpNotificationLocalLiveViewButton call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationLocalLiveViewButton failed, has nullptr");
        return;
    }
    std::vector<std::string> names = {};
    // names?: Array<string>
    if (GetPropertyStringArray(env, obj, "names", names, BUTTON_RESOURCE_SIZE) == ANI_OK) {
        for (auto name: names) {
            button.addSingleButtonName(GetResizeStr(name, STR_MAX_SIZE));
        }
    } else {
        ANS_LOGD("UnWarpNotificationLocalLiveViewButton get names failed.");
    }
    // icons?: Array<image.PixelMap>
    std::vector<std::shared_ptr<PixelMap>> icons = {};
    if (ANI_OK == GetPixelMapArray(env, obj, "icons", icons, BUTTON_RESOURCE_SIZE)) {
        for (auto icon : icons) {
            button.addSingleButtonIcon(icon);
        }
    } else {
        ANS_LOGD("UnWarpNotificationLocalLiveViewButton get icons failed.");
    }
    // iconsResource?: Array<Resource>
    std::vector<ResourceManager::Resource> resources = {};
    if (ANI_OK == GetResourceArray(env, obj, "iconsResource", resources, BUTTON_RESOURCE_SIZE)) {
        for (auto res : resources) {
            std::shared_ptr<ResourceManager::Resource> pRes = std::make_shared<ResourceManager::Resource>(res);
            button.addSingleButtonIconResource(pRes);
        }
    } else {
        ANS_LOGD("UnWarpNotificationLocalLiveViewButton get iconsResource failed.");
    }
    ANS_LOGD("UnWarpNotificationLocalLiveViewButton end");
}

bool WarpNotificationLocalLiveViewButton(
    ani_env *env, const NotificationLocalLiveViewButton &button, ani_object &buttonObject)
{
    if (env == nullptr) {
        ANS_LOGE("WarpNotificationLocalLiveViewButton failed, env is nullptr");
        return false;
    }
    ani_class buttonClass = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationButtonInner", buttonClass, buttonObject)
        || buttonObject == nullptr) {
        ANS_LOGE("WarpNotificationLocalLiveViewButton: create class failed");
        return false;
    }
    std::vector<std::string> names = button.GetAllButtonNames();
    if (!names.empty()) {
        ani_object namesObjectArray = GetAniStringArrayByVectorString(env, names);
        if (namesObjectArray == nullptr) {
            ANS_LOGE("namesObjectArray is nullptr");
            return false;
        }
        if (!SetPropertyByRef(env, buttonObject, "names", namesObjectArray)) {
            ANS_LOGE("Set names failed");
            return false;
        }
    }
    std::vector<std::shared_ptr<Media::PixelMap>> icons = button.GetAllButtonIcons();
    if (!icons.empty()) {
        ani_object iconsObjectArray = GetAniArrayPixelMap(env, icons);
        if (iconsObjectArray == nullptr) {
            ANS_LOGE("iconsObjectArray is nullptr");
            return false;
        }
        if (!SetPropertyByRef(env, buttonObject, "icons", iconsObjectArray)) {
            ANS_LOGE("Set icons failed");
            return false;
        }
    }
    std::vector<std::shared_ptr<ResourceManager::Resource>> iconsResource = button.GetAllButtonIconResource();
    if (!iconsResource.empty()) {
        ani_object resourceObjectArray = GetAniArrayResource(env, iconsResource);
        if (resourceObjectArray == nullptr) {
            ANS_LOGE("resourceObjectArray is nullptr");
            return false;
        }
        if (!SetPropertyByRef(env, buttonObject, "iconsResource", resourceObjectArray)) {
            ANS_LOGE("Set iconsResource failed");
            return false;
        }
    }
    return true;
}

bool getCapsuleByIcon(ani_env *env, ani_object obj, std::shared_ptr<PixelMap> &pixelMap)
{
    ani_boolean isUndefined = ANI_FALSE;
    ani_ref tempRef = nullptr;
    ani_status status = GetPropertyRef(env, obj, "icon", isUndefined, tempRef);
    if (status != ANI_OK) {
        ANS_LOGE("icon GetPropertyRef failed");
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        return true;
    }
    if (tempRef == nullptr) {
        ANS_LOGE("tempRef is null");
        return false;
    }
    pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(tempRef));
    if (pixelMap == nullptr) {
        ANS_LOGE("PixelMap is null");
        return false;
    }
    return true;
}

bool getCapsuleByButtons(ani_env *env, ani_object obj, std::vector<NotificationIconButton> &iconButtons)
{
    if (GetIconButtonArray(env, obj, "capsuleButtons", iconButtons, CAPSULE_BTN_MAX_SIZE) != ANI_OK) {
        ANS_LOGE("get capsuleButtons failed");
        return false;
    }

    return true;
}

bool getCapsuleByString(ani_env *env, ani_object obj, const char *name, std::string &out)
{
    ani_boolean isUndefined = ANI_TRUE;
    out = "";
    ani_status status = ANI_ERROR;
    status = GetPropertyString(env, obj, name, isUndefined, out);
    if (status != ANI_OK) {
        ANS_LOGE("%{public}s GetPropertyString failed", name);
        return false;
    }
    return true;
}

bool getCapsuleByInt(ani_env *env, ani_object obj, const char *name, int32_t &out)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref refObj;
    ani_status status = GetPropertyRef(env, obj, name, isUndefined, refObj);
    if (status != ANI_OK) {
        ANS_LOGE("%{public}s is undefined", name);
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        return true;
    }
    if ((status = env->Object_CallMethodByName_Int(static_cast<ani_object>(refObj),
        "unboxed", ":i", &out)) != ANI_OK) {
        ANS_LOGE("Object_CallMethodByName_Int failed, status : %{public}d", status);
        return false;
    }
    return true;
}

bool UnWarpNotificationCapsule(ani_env *env, ani_object obj, NotificationCapsule &capsule)
{
    ANS_LOGD("UnWarpNotificationCapsule call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationCapsule failed, has nullptr");
        return false;
    }
    std::string tempStr = "";
    if (!getCapsuleByString(env, obj, "title", tempStr)) {
        ANS_LOGE("get title failed");
        return false;
    }
    capsule.SetTitle(GetResizeStr(tempStr, STR_MAX_SIZE));

    if (!getCapsuleByString(env, obj, "backgroundColor", tempStr)) {
        ANS_LOGE("get backgroundColor failed");
        return false;
    }
    capsule.SetBackgroundColor(GetResizeStr(tempStr, STR_MAX_SIZE));

    if (!getCapsuleByString(env, obj, "content", tempStr)) {
        ANS_LOGE("get content failed");
        return false;
    }
    capsule.SetContent(GetResizeStr(tempStr, STR_MAX_SIZE));

    ani_int time = 0;
    if (!getCapsuleByInt(env, obj, "time", time)) {
        ANS_LOGE("get content failed");
        return false;
    }
    capsule.SetTime(static_cast<int32_t>(time));
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    if (!getCapsuleByIcon(env, obj, pixelMap)) {
        ANS_LOGE("get icon failed");
        return false;
    }
    if (pixelMap != nullptr) {
        capsule.SetIcon(pixelMap);
    }
    std::vector<NotificationIconButton> iconButtons = {};
    if (!getCapsuleByButtons(env, obj, iconButtons)) {
        ANS_LOGE("get capsuleButtons failed");
        return false;
    }
    capsule.SetCapsuleButton(iconButtons);
    return true;
}

ani_object WarpNotificationIconButton(ani_env *env, const NotificationIconButton &button)
{
    ANS_LOGD("WarpNotificationIconButton call");
    if (env == nullptr) {
        ANS_LOGE("WarpNotificationIconButton failed, env is nullptr");
        return nullptr;
    }
    ani_class iconButtonCls = nullptr;
    ani_object iconButtonObject = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationIconButtonInner", iconButtonCls, iconButtonObject)
        || iconButtonObject == nullptr) {
        ANS_LOGE("WarpNotificationIconButton: create class failed");
        return nullptr;
    }
    // name: string
    if (!SetPropertyOptionalByString(env, iconButtonObject, "name", button.GetName())) {
        ANS_LOGE("WarpNotificationIconButton: set name failed");
        return nullptr;
    }
    // iconResource: IconType;    type IconType = Resource | image.PixelMap;
    std::shared_ptr<Media::PixelMap> icon = button.GetIconImage();
    if (icon) {
        ani_object pixelMapObject = CreateAniPixelMap(env, icon);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("WarpNotificationIconButton: pixelMapObject is nullptr");
            return nullptr;
        }
        if (!SetPropertyByRef(env, iconButtonObject, "iconResource", pixelMapObject)) {
            ANS_LOGE("WarpNotificationIconButton: set iconResource failed");
            return nullptr;
        }
    } else {
        ani_object resourceObject = GetAniResource(env, button.GetIconResource());
        if (resourceObject == nullptr) {
            ANS_LOGE("WarpNotificationIconButton: resourceObject is nullptr");
            return nullptr;
        }
        if (!SetPropertyByRef(env, iconButtonObject, "iconResource", resourceObject)) {
            ANS_LOGE("WarpNotificationIconButton: set iconResource failed");
            return nullptr;
        }
    }
    // text?: string;
    SetPropertyOptionalByString(env, iconButtonObject, "text", button.GetText());
    // hidePanel?: boolean;
    SetPropertyOptionalByBoolean(env, iconButtonObject, "hidePanel", button.GetHidePanel());
    ANS_LOGD("WarpNotificationIconButton end");
    return iconButtonObject;
}

ani_object GetAniIconButtonArray(ani_env *env, const std::vector<NotificationIconButton> buttons)
{
    ANS_LOGD("GetAniIconButtonArray start");
    if (env == nullptr || buttons.empty()) {
        ANS_LOGE("GetAniIconButtonArray failed, env is nullptr or buttons is empty");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, buttons.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniIconButtonArray failed, arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &button : buttons) {
        ani_object item = WarpNotificationIconButton(env, button);
        if (item == nullptr) {
            ANS_LOGE("GetAniIconButtonArray: item is nullptr");
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", index, item)) {
            ANS_LOGE("GetAniIconButtonArray: add item failed");
            return nullptr;
        }
        index ++;
    }
    ANS_LOGE("GetAniIconButtonArray end");
    return arrayObj;
}

bool WarpNotificationCapsule(ani_env *env, const NotificationCapsule &capsule, ani_object &capsuleObject)
{
    ANS_LOGD("WarpNotificationCapsule start");
    if (env == nullptr) {
        ANS_LOGE("GetAniIconButtonArray failed, env is nullptr");
        return false;
    }
    ani_class capsuleClass = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationCapsuleInner", capsuleClass, capsuleObject)
        || capsuleObject == nullptr) {
        ANS_LOGE("GetAniIconButtonArray: create class failed");
        return false;
    }
    // title?: string;
    SetPropertyOptionalByString(env, capsuleObject, "title", capsule.GetTitle());
    // icon?: image.PixelMap;
    std::shared_ptr<Media::PixelMap> icon = capsule.GetIcon();
    if (icon) {
        ani_object pixelMapObject = CreateAniPixelMap(env, icon);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("CreatePixelMap failed, pixelMapObject is nullptr");
        } else {
            SetPropertyByRef(env, capsuleObject, "icon", pixelMapObject);
        }
    }
    // backgroundColor?: string;
    if (!SetPropertyOptionalByString(env, capsuleObject, "backgroundColor", capsule.GetBackgroundColor())) {
        ANS_LOGD("WarpNotificationCapsule: set backgroundColor failed");
    }
    //content?: string;
    if (!SetPropertyOptionalByString(env, capsuleObject, "content", capsule.GetContent())) {
        ANS_LOGD("WarpNotificationCapsule: set content failed");
    }
    // time?: int;
    if (!SetPropertyOptionalByInt(env, capsuleObject, "time", capsule.GetTime())) {
        ANS_LOGD("WarpNotificationCapsule: set time failed");
    }
    // capsuleButtons?: Array<NotificationIconButton>;
    std::vector<NotificationIconButton> buttons = capsule.GetCapsuleButton();
    ani_object buttonsObjectArray = GetAniIconButtonArray(env, buttons);
    if (buttonsObjectArray == nullptr
        || SetPropertyByRef(env, capsuleObject, "capsuleButtons", buttonsObjectArray)) {
        ANS_LOGD("WarpNotificationCapsule: set capsuleButtons failed");
    }
    ANS_LOGD("WarpNotificationCapsule end");
    return true;
}

ani_status UnWarpNotificationBasicContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationBasicContent> basicContent)
{
    ANS_LOGD("UnWarpNotificationBasicContent call");
    if (env == nullptr || obj == nullptr || basicContent == nullptr) {
        ANS_LOGE("UnWarpNotificationBasicContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    std::string title;
    if ((status = GetPropertyString(env, obj, "title", isUndefined, title)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationBasicContent: get title failed, status = %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    basicContent->SetTitle(GetResizeStr(title, SHORT_TEXT_SIZE));
    std::string text;
    if ((status = GetPropertyString(env, obj, "text", isUndefined, text)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationBasicContent: get text failed, status = %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    basicContent->SetText(GetResizeStr(text, COMMON_TEXT_SIZE));
    std::string additionalText;
    if (GetPropertyString(env, obj, "additionalText", isUndefined, additionalText) == ANI_OK
        && isUndefined == ANI_FALSE) {
        basicContent->SetAdditionalText(GetResizeStr(additionalText, COMMON_TEXT_SIZE));
    } else {
        ANS_LOGD("UnWarpNotificationBasicContent: get additionalText failed");
    }
    ani_ref lockscreenPictureRef = {};
    isUndefined = ANI_TRUE;
    if (GetPropertyRef(env, obj, "lockscreenPicture", isUndefined, lockscreenPictureRef) != ANI_OK
        || isUndefined == ANI_TRUE || lockscreenPictureRef == nullptr) {
        ANS_LOGD("UnWarpNotificationBasicContent: get lockscreenPicture failed");
    } else {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(lockscreenPictureRef));
        if (pixelMap != nullptr) {
            basicContent->SetLockScreenPicture(pixelMap);
        } else {
            ANS_LOGD("UnWarpNotificationBasicContent: get lockscreenPicture by pixelMap failed");
        }
    }
    ANS_LOGD("UnWarpNotificationBasicContent end");
    return status;
}

ani_status UnWarpNotificationNormalContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationNormalContent> &normalContent)
{
    ANS_LOGD("UnWarpNotificationNormalContent call");
    if (env == nullptr || obj == nullptr || normalContent == nullptr) {
        ANS_LOGE("UnWarpNotificationNormalContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, normalContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationNormalContent failed");
        return status;
    }
    ANS_LOGE("UnWarpNotificationNormalContent end");
    return status;
}

ani_status UnWarpNotificationLongTextContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLongTextContent> &longTextContent)
{
    ANS_LOGD("UnWarpNotificationLongTextContent call");
    if (env == nullptr || obj == nullptr || longTextContent == nullptr) {
        ANS_LOGE("UnWarpNotificationLongTextContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, longTextContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLongTextContent:get BasicContent failed");
        return status;
    }
    ani_boolean isUndefined = ANI_TRUE;
    std::string longText;
    if ((status = GetPropertyString(env, obj, "longText", isUndefined, longText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationLongTextContent:get longText failed");
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetLongText(GetResizeStr(longText, COMMON_TEXT_SIZE));
    std::string briefText;
    if ((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationLongTextContent:get briefText failed");
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetBriefText(GetResizeStr(briefText, SHORT_TEXT_SIZE));
    std::string expandedTitle;
    if ((status = GetPropertyString(env, obj, "expandedTitle", isUndefined, expandedTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationLongTextContent:get expandedTitle failed");
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetExpandedTitle(GetResizeStr(expandedTitle, SHORT_TEXT_SIZE));
    ANS_LOGD("UnWarpNotificationLongTextContent end");
    return status;
}

ani_status UnWarpNotificationMultiLineContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationMultiLineContent> &multiLineContent)
{
    ANS_LOGD("UnWarpNotificationMultiLineContent call");
    if (env == nullptr || obj == nullptr || multiLineContent == nullptr) {
        ANS_LOGE("UnWarpNotificationMultiLineContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, multiLineContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationMultiLineContent: get BasicContent failed");
        return status;
    }
    ani_boolean isUndefined = ANI_TRUE;
    std::string longTitle;
    if ((status = GetPropertyString(env, obj, "longTitle", isUndefined, longTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationMultiLineContent: get longTitle failed");
        return ANI_INVALID_ARGS;
    }
    multiLineContent->SetExpandedTitle(GetResizeStr(longTitle, SHORT_TEXT_SIZE));
    std::string briefText;
    isUndefined = ANI_TRUE;
    if ((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationMultiLineContent: get briefText failed");
        return ANI_INVALID_ARGS;
    }
    multiLineContent->SetBriefText(GetResizeStr(briefText, SHORT_TEXT_SIZE));
    std::vector<std::string> lines = {};
    if ((status = GetPropertyStringArray(env, obj, "lines", lines)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationMultiLineContent: get lines failed");
        return ANI_INVALID_ARGS;
    }
    for (auto line : lines) {
        multiLineContent->AddSingleLine(GetResizeStr(line, SHORT_TEXT_SIZE));
    }
    std::vector<std::shared_ptr<WantAgent>> lineWantAgents = {};
    isUndefined = ANI_TRUE;
    if ((status = GetPropertyWantAgentArray(env, obj, "lineWantAgents", isUndefined, lineWantAgents)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationMultiLineContent: get lineWantAgents failed");
        return ANI_INVALID_ARGS;
    }
    ANS_LOGD("UnWarpNotificationMultiLineContent end");
    return status;
}

ani_status UnWarpNotificationPictureContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationPictureContent> &pictureContent)
{
    ANS_LOGD("UnWarpNotificationPictureContent call");
    if (env == nullptr || obj == nullptr || pictureContent == nullptr) {
        ANS_LOGE("UnWarpNotificationPictureContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, pictureContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationPictureContent: get BasicContent failed");
        return status;
    }
    std::string expandedTitle;
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = GetPropertyString(env, obj, "expandedTitle", isUndefined, expandedTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationPictureContent: get expandedTitle failed");
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetExpandedTitle(GetResizeStr(expandedTitle, SHORT_TEXT_SIZE));

    std::string briefText;
    if ((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationPictureContent: get briefText failed");
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetBriefText(GetResizeStr(briefText, SHORT_TEXT_SIZE));
    ani_ref pictureRef = {};
    if ((status = GetPropertyRef(env, obj, "picture", isUndefined, pictureRef)) != ANI_OK
        || isUndefined == ANI_TRUE || pictureRef == nullptr) {
        ANS_LOGE("UnWarpNotificationPictureContent: get briefText failed");
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(pictureRef));
    if (pixelMap == nullptr) {
        ANS_LOGE("UnWarpNotificationPictureContent: get briefText by pixelMap failed");
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetBigPicture(pixelMap);
    ANS_LOGD("UnWarpNotificationPictureContent end");
    return status;
}

bool CheckAniLiveViewContentParam(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (env == nullptr) {
        ANS_LOGE("env is null");
        return false;
    }
    if (obj == nullptr) {
        ANS_LOGE("obj is null");
        return false;
    }
    if (liveViewContent == nullptr) {
        ANS_LOGE("liveViewContent is null");
        return false;
    }
    return true;
}

void GetAniLiveViewContentVersion(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (!CheckAniLiveViewContentParam(env, obj, liveViewContent)) {
        ANS_LOGE("CheckAniLiveViewContentParam faild");
        return;
    }
    ani_int versionAni = 0;
    ani_boolean isUndefined = ANI_TRUE;
    if (GetPropertyInt(env, obj, "version", isUndefined, versionAni) != ANI_OK
        || isUndefined == ANI_TRUE) {
            ANS_LOGE("UnWarpNotificationLiveViewContent: get version failed");
            return;
        }
    liveViewContent->SetVersion(static_cast<uint32_t>(versionAni));
}

void GetAniLiveViewContentExtraInfo(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (!CheckAniLiveViewContentParam(env, obj, liveViewContent)) {
        ANS_LOGE("CheckAniLiveViewContentParam faild");
        return;
    }
    ani_status status = ANI_OK;
    ani_ref extraInfoRef;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK != (status = GetPropertyRef(env, obj, "extraInfo", isUndefined, extraInfoRef))
        || isUndefined == ANI_TRUE || extraInfoRef == nullptr) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get extraInfo failed. status %{public}d", status);
        return;
    }
    AAFwk::WantParams wantParams = {};
    if (!UnwrapWantParams(env, extraInfoRef, wantParams)) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get extraInfo by ref failed");
        return;
    }
    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<WantParams>(wantParams);
    liveViewContent->SetExtraInfo(extraInfo);
}

void GetAniLiveViewContentPictureInfo(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (!CheckAniLiveViewContentParam(env, obj, liveViewContent)) {
        ANS_LOGE("CheckAniLiveViewContentParam faild");
        return;
    }
    ani_ref pictureInfoRef;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK != GetPropertyRef(env, obj, "pictureInfo", isUndefined, pictureInfoRef)
        || isUndefined == ANI_TRUE || pictureInfoRef == nullptr) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get pictureInfo failed");
        return;
    }
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap;
    if (GetMapOfPictureInfo(env, static_cast<ani_object>(pictureInfoRef), pictureMap) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get pictureInfo by ref failed");
        return;
    }
    liveViewContent->SetPicture(pictureMap);
}

void GetAniLiveViewContentIsLocalUpdateOnly(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (!CheckAniLiveViewContentParam(env, obj, liveViewContent)) {
        ANS_LOGE("CheckAniLiveViewContentParam faild");
        return;
    }
    ani_status status = ANI_OK;
    bool isLocalUpdateOnly = true;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK != (status = GetPropertyBool(env, obj, "isLocalUpdateOnly", isUndefined, isLocalUpdateOnly))) {
        ANS_LOGE("get 'isLocalUpdateOnly' faild. status %{public}d", status);
        return;
    }
    if (isUndefined == ANI_TRUE) {
        ANS_LOGE("'isLocalUpdateOnly' is Undefined");
        return;
    }
    liveViewContent->SetIsOnlyLocalUpdate(isLocalUpdateOnly);
}

void UnWarpNotificationLiveViewContentByOther(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    ANS_LOGD("UnWarpNotificationLiveViewContentByOther call");
    if (!CheckAniLiveViewContentParam(env, obj, liveViewContent)) {
        ANS_LOGE("CheckAniLiveViewContentParam faild");
        return;
    }
    GetAniLiveViewContentVersion(env, obj, liveViewContent);
    GetAniLiveViewContentExtraInfo(env, obj, liveViewContent);
    GetAniLiveViewContentPictureInfo(env, obj, liveViewContent);
    GetAniLiveViewContentIsLocalUpdateOnly(env, obj, liveViewContent);
    ANS_LOGD("UnWarpNotificationLiveViewContentByOther end");
}

ani_status UnWarpNotificationLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    ANS_LOGD("UnWarpNotificationLiveViewContent call");
    if (env == nullptr || obj == nullptr || liveViewContent == nullptr) {
        ANS_LOGE("UnWarpNotificationLiveViewContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, liveViewContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get BasicContent failed");
        return status;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref statusRef;
    if ((status = GetPropertyRef(env, obj, "status", isUndefined, statusRef)) != ANI_OK
        || isUndefined == ANI_TRUE || statusRef == nullptr) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get status failed");
        return ANI_INVALID_ARGS;
    }
    LiveViewStatus liveViewStatus = LiveViewStatus::LIVE_VIEW_CREATE;
    if (!LiveViewStatusEtsToC(env, static_cast<ani_enum_item>(statusRef), liveViewStatus)) {
        ANS_LOGE("UnWarpNotificationLiveViewContent: get status by ref failed");
        return ANI_INVALID_ARGS;
    }
    liveViewContent->SetLiveViewStatus(liveViewStatus);
    UnWarpNotificationLiveViewContentByOther(env, obj, liveViewContent);
    ANS_LOGD("UnWarpNotificationLiveViewContent end");
    return status;
}

bool GetLocalLiveViewContentByOne(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent)
{
    ANS_LOGD("GetLocalLiveViewContentByOne call");
    if (env == nullptr || obj == nullptr || localLiveViewContent == nullptr) {
        ANS_LOGE("GetLocalLiveViewContentByOne failed, has nullptr");
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref capsuleRef = {};
    if (GetPropertyRef(env, obj, "capsule", isUndefined, capsuleRef) == ANI_OK
        && isUndefined == ANI_FALSE && capsuleRef != nullptr) {
        NotificationCapsule capsule;
        if (!UnWarpNotificationCapsule(env, static_cast<ani_object>(capsuleRef), capsule)) {
            return false;
        }
        localLiveViewContent->SetCapsule(capsule);
        localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);
    }
    ani_ref buttonRef = {};
    if (GetPropertyRef(env, obj, "button", isUndefined, buttonRef) == ANI_OK
        && isUndefined == ANI_FALSE && buttonRef != nullptr) {
        NotificationLocalLiveViewButton button;
        UnWarpNotificationLocalLiveViewButton(env, static_cast<ani_object>(buttonRef), button);
        localLiveViewContent->SetButton(button);
        localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
    } else {
        ANS_LOGD("GetLocalLiveViewContentByOne: get button failed");
    }
    std::vector<NotificationIconButton> buttons = {};
    if (GetIconButtonArray(env, obj, "cardButtons", buttons, BUTTON_MAX_SIZE) == ANI_OK) {
        localLiveViewContent->SetCardButton(buttons);
        localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CARD_BUTTON);
    } else {
        ANS_LOGD("GetLocalLiveViewContentByOne: get cardButtons failed");
    }
    ANS_LOGD("GetLocalLiveViewContentByOne end");
    return true;
}

void GetLocalLiveViewContentByTwo(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent)
{
    ANS_LOGD("GetLocalLiveViewContentByTwo call");
    if (env == nullptr || obj == nullptr || localLiveViewContent == nullptr) {
        ANS_LOGE("GetLocalLiveViewContentByTwo failed, has nullptr");
        return;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref timeRef = {};
    if (GetPropertyRef(env, obj, "time", isUndefined, timeRef) == ANI_OK
        && isUndefined == ANI_FALSE && timeRef != nullptr) {
        NotificationTime notificationTime;
        UnWarpNotificationTime(env, static_cast<ani_object>(timeRef), notificationTime);
        localLiveViewContent->SetTime(notificationTime);
        localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);
    } else {
        ANS_LOGD("GetLocalLiveViewContentByTwo: get time failed");
    }
    ani_ref progressRef = {};
    if (GetPropertyRef(env, obj, "progress", isUndefined, progressRef) == ANI_OK
        && isUndefined == ANI_FALSE && progressRef != nullptr) {
        NotificationProgress notificationProgress;
        UnWarpNotificationProgress(env, static_cast<ani_object>(progressRef), notificationProgress);
        localLiveViewContent->SetProgress(notificationProgress);
        localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS);
    } else {
        ANS_LOGD("GetLocalLiveViewContentByTwo: get progress failed");
    }
    ani_ref liveViewTypeRef = {};
    if (GetPropertyRef(env, obj, "liveViewType", isUndefined, liveViewTypeRef) == ANI_OK
        && isUndefined == ANI_FALSE && liveViewTypeRef != nullptr) {
        LiveViewTypes types = LiveViewTypes::LIVE_VIEW_ACTIVITY;
        if (LiveViewTypesEtsToC(env, static_cast<ani_enum_item>(liveViewTypeRef), types)) {
            localLiveViewContent->SetLiveViewType(types);
        } else {
            ANS_LOGD("GetLocalLiveViewContentByTwo: get liveViewType by ref failed");
        }
    } else {
        ANS_LOGD("GetLocalLiveViewContentByTwo: get liveViewType failed");
    }
    ANS_LOGD("GetLocalLiveViewContentByTwo end");
}

ani_status UnWarpNotificationLocalLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent)
{
    ANS_LOGD("UnWarpNotificationLocalLiveViewContent call");
    if (env == nullptr || obj == nullptr || localLiveViewContent == nullptr) {
        ANS_LOGE("UnWarpNotificationLocalLiveViewContent failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    if ((status = UnWarpNotificationBasicContent(env, obj, localLiveViewContent)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLocalLiveViewContent: get BasicContent failed");
        return status;
    }
    ani_int typeCode = 0;
    if ((status = env->Object_GetPropertyByName_Int(obj, "typeCode", &typeCode)) != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLocalLiveViewContent: get typeCode failed, status = %{public}d", status);
        return ANI_INVALID_ARGS;
    }
    localLiveViewContent->SetType(typeCode);
    if (!GetLocalLiveViewContentByOne(env, obj, localLiveViewContent)) {
        return ANI_INVALID_ARGS;
    }
    GetLocalLiveViewContentByTwo(env, obj, localLiveViewContent);
    ANS_LOGD("UnWarpNotificationLocalLiveViewContent end");
    return status;
}

bool SetNotificationBasicContent(
    ani_env* env, const NotificationBasicContent *basicContent, ani_object &object)
{
    ANS_LOGD("SetNotificationBasicContent call");
    if (env == nullptr || basicContent == nullptr || object == nullptr) {
        ANS_LOGE("SetNotificationBasicContent failed, has nullptr");
        return false;
    }
    if (!SetPropertyOptionalByString(env, object, "title", basicContent->GetTitle())) {
        ANS_LOGE("SetNotificationBasicContent: set title failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, object, "text", basicContent->GetText())) {
        ANS_LOGE("SetNotificationBasicContent: set text failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, object, "additionalText", basicContent->GetAdditionalText())) {
        ANS_LOGD("SetNotificationBasicContent: set additionalText failed");
    }
    ani_ref lockScreenPicObj = CreateAniPixelMap(env, basicContent->GetLockScreenPicture());
    if (lockScreenPicObj == nullptr || !SetPropertyByRef(env, object, "lockScreenPicture", lockScreenPicObj)) {
        ANS_LOGD("SetNotificationBasicContent: set lockScreenPicture failed");
    }
    ANS_LOGD("SetNotificationBasicContent end");
    return true;
}

bool SetNotificationNormalContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationNormalContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationNormalContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationBasicContentInner", contentCls, contentObj)
        || contentCls == nullptr || contentObj == nullptr) {
        ANS_LOGE("SetNotificationNormalContent: create class failed");
        return false;
    }
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    if (basicContent == nullptr) {
        ANS_LOGE("SetNotificationNormalContent: get basicContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, basicContent.get(), contentObj)) {
        ANS_LOGE("SetNotificationNormalContent: set basicContent failed");
        return false;
    }
    if (!SetPropertyByRef(env, ncObj, "normal", contentObj)) {
        ANS_LOGE("SetNotificationNormalContent: set normal to ncObj failed");
        return false;
    }
    return true;
}

bool SetNotificationLongTextContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationLongTextContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationLongTextContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationLongTextContentInner", contentCls, contentObj)
        || contentObj == nullptr) {
        ANS_LOGE("SetNotificationLongTextContent: create class failed");
        return false;
    }
    auto content = std::reinterpret_pointer_cast<NotificationLongTextContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationLongTextContent: get LongTextContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, content.get(), contentObj)) {
        ANS_LOGE("SetNotificationLongTextContent: set BasicContent failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, contentObj, "longText", content->GetLongText())) {
        ANS_LOGE("SetNotificationLongTextContent: set longText failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, contentObj, "briefText", content->GetBriefText())) {
        ANS_LOGE("SetNotificationLongTextContent: set briefText failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, contentObj, "expandedTitle", content->GetExpandedTitle())) {
        ANS_LOGE("SetNotificationLongTextContent: set expandedTitle failed");
        return false;
    }
    return SetPropertyByRef(env, ncObj, "longText", contentObj);
}

bool SetNotificationPictureContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationPictureContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationPictureContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationPictureContentInner", contentCls, contentObj)
        || contentObj == nullptr) {
        ANS_LOGE("SetNotificationPictureContent: create class failed");
        return false;
    }
    auto content = std::reinterpret_pointer_cast<NotificationPictureContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationPictureContent: get PictureContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, content.get(), contentObj)) {
        ANS_LOGE("SetNotificationPictureContent: set BasicContent failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, contentObj, "briefText", content->GetBriefText())) {
        ANS_LOGD("SetNotificationPictureContent: set briefText failed");
    }
    if (!SetPropertyOptionalByString(env, contentObj, "expandedTitle", content->GetExpandedTitle())) {
        ANS_LOGD("SetNotificationPictureContent: set expandedTitle failed");
    }
    ani_object pictureObj = CreateAniPixelMap(env, content->GetBigPicture());
    if (pictureObj == nullptr || !SetPropertyByRef(env, contentObj, "picture", pictureObj)) {
        ANS_LOGD("SetNotificationPictureContent: set picture failed");
    }
    return SetPropertyByRef(env, ncObj, "picture", contentObj);
}

bool SetNotificationMultiLineContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationMultiLineContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationMultiLineContentInner", contentCls, contentObj)
        || contentObj == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent: create class failed");
        return false;
    }
    auto content = std::reinterpret_pointer_cast<NotificationMultiLineContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent: get MultiLineContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, content.get(), contentObj)) {
        ANS_LOGE("SetNotificationMultiLineContent: set BasicContent failed");
        return false;
    }
    if (!SetPropertyOptionalByString(env, contentObj, "briefText", content->GetBriefText())) {
        ANS_LOGD("SetNotificationMultiLineContent: set briefText failed");
    }
    if (!SetPropertyOptionalByString(env, contentObj, "longTitle", content->GetExpandedTitle())) {
        ANS_LOGD("SetNotificationMultiLineContent: set briefText failed");
    }
    std::vector<std::string> allLines = content->GetAllLines();
    ani_object allLinesObject = GetAniStringArrayByVectorString(env, allLines);
    if (allLinesObject == nullptr || !SetPropertyByRef(env, contentObj, "lines", allLinesObject)) {
        ANS_LOGD("SetNotificationMultiLineContent: set lines failed");
    }
    std::vector<std::shared_ptr<WantAgent>> lineWantAgents = content->GetLineWantAgents();
    if (lineWantAgents.size() > 0) {
        ani_object lineWantAgentsObj = GetAniWantAgentArray(env, lineWantAgents);
        if (lineWantAgentsObj == nullptr ||
            !SetPropertyByRef(env, contentObj, "lineWantAgents", lineWantAgentsObj)) {
            ANS_LOGD("SetNotificationMultiLineContent set lineWantAgents faild");
        }
    }
    return SetPropertyByRef(env, ncObj, "multiLine", contentObj);
}

void SetCapsule(ani_env *env, std::shared_ptr<NotificationLocalLiveViewContent> &content, ani_object &contentObj)
{
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE)) {
        ani_object capsuleObject = nullptr;
        if (!WarpNotificationCapsule(env, content->GetCapsule(), capsuleObject)
            || capsuleObject == nullptr || !SetPropertyByRef(env, contentObj, "capsule", capsuleObject)) {
            ANS_LOGD("SetNotificationMultiLineContent: set capsule failed");
        }
    }
}

void SetButton(ani_env *env, std::shared_ptr<NotificationLocalLiveViewContent> &content, ani_object &contentObj)
{
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON)) {
        ani_object buttonObject = nullptr;
        if (!WarpNotificationLocalLiveViewButton(env, content->GetButton(), buttonObject)
            || buttonObject == nullptr || !SetPropertyByRef(env, contentObj, "button", buttonObject)) {
            ANS_LOGD("SetNotificationMultiLineContent: set button failed");
        }
    }
}

void SetCardButtons(ani_env *env, std::shared_ptr<NotificationLocalLiveViewContent> &content, ani_object &contentObj)
{
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CARD_BUTTON)) {
        std::vector<NotificationIconButton> buttons = content->GetCardButton();
        ani_object buttonsObjectArray = GetAniIconButtonArray(env, buttons);
        if (buttonsObjectArray == nullptr || !SetPropertyByRef(env, contentObj, "cardButtons", buttonsObjectArray)) {
            ANS_LOGD("SetNotificationMultiLineContent: set cardButtons failed");
        }
    }
}

void SetProgress(ani_env *env, std::shared_ptr<NotificationLocalLiveViewContent> &content, ani_object &contentObj)
{
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS)) {
        ani_object progressObject = nullptr;
        if (!WarpNotificationProgress(env, content->GetProgress(), progressObject)
            || progressObject == nullptr || !SetPropertyByRef(env, contentObj, "progress", progressObject)) {
            ANS_LOGD("SetNotificationMultiLineContent: set progress failed");
        }
    }
}

void SetTime(ani_env *env, std::shared_ptr<NotificationLocalLiveViewContent> &content, ani_object &contentObj)
{
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::TIME)) {
        bool flag = content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
        ani_object timeObject = nullptr;
        if (!WarpNotificationTime(env, content->GetTime(), flag, timeObject)
            || timeObject == nullptr || !SetPropertyByRef(env, contentObj, "time", timeObject)) {
            ANS_LOGD("SetNotificationMultiLineContent: set time failed");
        }
    }
}

bool WarpLocalLiveViewContentWithFalg(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &contentObj)
{
    auto content = std::reinterpret_pointer_cast<NotificationLocalLiveViewContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent: get LocalLiveViewContent failed");
        return false;
    }
    SetCapsule(env, content, contentObj);
    SetButton(env, content, contentObj);
    SetCardButtons(env, content, contentObj);
    SetProgress(env, content, contentObj);
    SetTime(env, content, contentObj);
    return true;
}


bool WarpNotificationLocalLiveViewContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &contentObj)
{
    auto content = std::reinterpret_pointer_cast<NotificationLocalLiveViewContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent: get LocalLiveViewContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, content.get(), contentObj)) {
        ANS_LOGE("SetNotificationMultiLineContent: set BasicContent failed");
        return false;
    }
    if (!SetPropertyOptionalByInt(env, contentObj, "typeCode", content->GetType())) {
        ANS_LOGD("SetNotificationMultiLineContent: set typeCode failed");
    }
    ani_enum_item enumItem = nullptr;
    if (!LiveViewTypesCToEts(env, content->GetLiveViewType(), enumItem)
        || enumItem == nullptr || !SetPropertyByRef(env, contentObj, "liveViewType", enumItem)) {
        ANS_LOGD("SetNotificationMultiLineContent: set liveViewType failed");
    }
    if (!WarpLocalLiveViewContentWithFalg(env, nContent, contentObj)) {
        ANS_LOGE("WarpLocalLiveViewContentWithFalg faild");
        return false;
    }
    return true;
}

bool SetNotificationLocalLiveViewContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationMultiLineContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env,
        "notification.notificationContent.NotificationSystemLiveViewContentInner", contentCls, contentObj)
        || contentObj == nullptr) {
        ANS_LOGE("SetNotificationMultiLineContent: create class failed");
        return false;
    }
    if (!WarpNotificationLocalLiveViewContent(env, nContent, contentObj)) {
        ANS_LOGE("WarpNotificationLocalLiveViewContent faild");
        return false;
    }
    return SetPropertyByRef(env, ncObj, "systemLiveView", contentObj);
}

bool WarpLiveViewContentBasicContent(
    ani_env *env, std::shared_ptr<NotificationContent> nContent, ani_object &contentObj)
{
    auto content = std::reinterpret_pointer_cast<NotificationLiveViewContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationLiveViewContent: get LiveViewContent failed");
        return false;
    }
    if (!SetNotificationBasicContent(env, content.get(), contentObj)) {
        ANS_LOGE("SetNotificationLiveViewContent: set BasicContent failed");
        return false;
    }
    return true;
}

bool WarpNotificationLiveViewContent(
    ani_env *env, std::shared_ptr<NotificationContent> nContent, ani_object &contentObj)
{
    if (!WarpLiveViewContentBasicContent(env, nContent, contentObj)) {
        ANS_LOGE("WarpLiveViewContentBasicContent faild");
        return false;
    }
    auto content = std::reinterpret_pointer_cast<NotificationLiveViewContent>(nContent->GetNotificationContent());
    if (content == nullptr) {
        ANS_LOGE("SetNotificationLiveViewContent: get LiveViewContent failed");
        return false;
    }
    ani_object lockScreenPicObj = CreateAniPixelMap(env, content->GetLockScreenPicture());
    if (lockScreenPicObj == nullptr || !SetPropertyByRef(env, contentObj, "lockScreenPicture", lockScreenPicObj)) {
        ANS_LOGD("SetNotificationLiveViewContent: set lockScreenPicture failed");
    }
    ani_enum_item enumItem = nullptr;
    if (!LiveViewStatusCToEts(env, content->GetLiveViewStatus(), enumItem)
        || enumItem == nullptr || !SetPropertyByRef(env, contentObj, "status", enumItem)) {
        ANS_LOGD("SetNotificationLiveViewContent: set status failed");
    }
    if (!SetPropertyOptionalByInt(env, contentObj, "version", static_cast<int32_t>(content->GetVersion()))) {
        ANS_LOGD("SetNotificationLiveViewContent: set version failed");
    }
    std::shared_ptr<AAFwk::WantParams> extraInfoData = content->GetExtraInfo();
    if (extraInfoData == nullptr) {
        ANS_LOGD("SetNotificationLiveViewContent: set extraInfo failed");
    } else {
        ani_ref extraInfoObj = WrapWantParams(env, *extraInfoData);
        if (extraInfoObj == nullptr || !SetPropertyByRef(env, contentObj, "extraInfo", extraInfoObj)) {
            ANS_LOGD("SetNotificationLiveViewContent: set extraInfo by ref failed");
        }
    }
    ani_object pictureInfoObj = nullptr;
    if (!GetAniPictrueInfo(env, content->GetPicture(), pictureInfoObj)
        || pictureInfoObj == nullptr || SetPropertyByRef(env, contentObj, "pictureInfo", pictureInfoObj)) {
        ANS_LOGD("SetNotificationLiveViewContent: set pictureInfo failed");
    }
    return true;
}

bool SetNotificationLiveViewContent(
    ani_env* env, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationLiveViewContent call");
    if (env == nullptr || nContent == nullptr || ncObj == nullptr) {
        ANS_LOGE("SetNotificationLiveViewContent failed, has nullptr");
        return false;
    }
    ani_class contentCls;
    ani_object contentObj;
    if (!CreateClassObjByClassName(env, "notification.notificationContent.NotificationLiveViewContentInner",
        contentCls, contentObj) || contentObj == nullptr) {
        ANS_LOGE("SetNotificationLiveViewContent: create class failed");
        return false;
    }
    if (!WarpNotificationLiveViewContent(env, nContent, contentObj)) {
        ANS_LOGE("WarpNotificationLiveViewContent faild");
        return false;
    }
    return SetPropertyByRef(env, ncObj, "liveView", contentObj);
}

bool SetNotificationContent(ani_env* env, std::shared_ptr<NotificationContent> ncContent, ani_object &ncObj)
{
    ANS_LOGD("SetNotificationContent call");
    if (env == nullptr || ncContent == nullptr) {
        ANS_LOGE("SetNotificationContent failed, has nullptr");
        return false;
    }
    ani_class ncCls;
    if (!CreateClassObjByClassName(env, "notification.notificationContent.NotificationContentInner",
        ncCls, ncObj) || ncObj == nullptr) {
        ANS_LOGE("SetNotificationContent: create class failed");
        return false;
    }
    ContentType contentType = ncContent->GetContentType();
    ani_enum_item contentTypeItem {};
    if (!ContentTypeCToEts(env, contentType, contentTypeItem)
        || !SetPropertyByRef(env, ncObj, "notificationContentType", contentTypeItem)) {
        ANS_LOGE("SetNotificationContent: set notificationContentType failed");
        return false;
    }
    bool result = true;
    ANS_LOGD("SetNotificationContent: contentType = %{public}d", static_cast<int>(contentType));
    switch (contentType) {
        case ContentType::BASIC_TEXT: // normal?: NotificationBasicContent
            result = SetNotificationNormalContent(env, ncContent, ncObj);
            break;
        case ContentType::LONG_TEXT: // longText?: NotificationLongTextContent
            result = SetNotificationLongTextContent(env, ncContent, ncObj);
            break;
        case ContentType::PICTURE: // picture?: NotificationPictureContent
            result = SetNotificationPictureContent(env, ncContent, ncObj);
            break;
        case ContentType::MULTILINE: // multiLine?: NotificationMultiLineContent
            result = SetNotificationMultiLineContent(env, ncContent, ncObj);
            break;
        case ContentType::LOCAL_LIVE_VIEW: // systemLiveView?: NotificationLocalLiveViewContent
            result = SetNotificationLocalLiveViewContent(env, ncContent, ncObj);
            break;
        case ContentType::LIVE_VIEW: // liveView?: NotificationLiveViewContent
            result = SetNotificationLiveViewContent(env, ncContent, ncObj);
            break;
        default:
            result = false;
            break;
    }
    if (!result) {
        ANS_LOGE("SetNotificationContent failed");
    }
    ANS_LOGD("SetNotificationContent end");
    return result;
}
} // namespace NotificationSts
} // OHOS
