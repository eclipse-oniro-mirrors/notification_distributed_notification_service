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
    STSLiveViewStatus stsLiveViewStatus = STSLiveViewStatus::LIVE_VIEW_CREATE;
    if(EnumConvertAniToNative(env, enumItem, stsLiveViewStatus)) {
        StsLiveViewStatusUtils::StsToC(stsLiveViewStatus, liveViewStatus);
        return true;
    }
    return false;
}

bool LiveViewStatusCToEts(ani_env *env, LiveViewStatus liveViewStatus, ani_enum_item &enumItem)
{
    STSLiveViewStatus stsLiveViewStatus = STSLiveViewStatus::LIVE_VIEW_CREATE;
    StsLiveViewStatusUtils::CToSts(liveViewStatus, stsLiveViewStatus);
    if(EnumConvertNativeToAni(env,
        "Lnotification/notificationContent/#LiveViewStatus", stsLiveViewStatus, enumItem)) {
        return true;
    }
    return false;
}

bool LiveViewTypesEtsToC(ani_env *env, ani_enum_item enumItem, LiveViewTypes &liveViewTypes)
{
    return EnumConvertAniToNative(env, enumItem, liveViewTypes);
}

bool LiveViewTypesCToEts(ani_env *env, LiveViewTypes liveViewTypes, ani_enum_item &enumItem)
{
    return EnumConvertNativeToAni(env,
        "Lnotification/notificationContent/#LiveViewTypes", liveViewTypes, enumItem);
}

void UnWarpNotificationProgress(ani_env *env, ani_object obj,
    NotificationProgress &notificationProgress)
{
    ani_double maxValueAni = 0.0;
    ani_boolean isUndefined = ANI_TRUE;
    if(GetPropertyDouble(env, obj, "maxValue", isUndefined, maxValueAni) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetMaxValue(static_cast<int32_t>(maxValueAni));
    }
    ani_double currentValueAni = 0.0;
    if(GetPropertyDouble(env, obj, "currentValue", isUndefined, currentValueAni) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetCurrentValue(static_cast<int32_t>(currentValueAni));
    }

    bool isPercentage = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isPercentage", isUndefined, isPercentage)
        && isUndefined == ANI_FALSE) {
        notificationProgress.SetIsPercentage(isPercentage);
    }
}

bool WarpNotificationProgress(ani_env *env, const NotificationProgress &progress, ani_object &progressObject)
{
    ani_class progressClass = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationProgressInner;", progressClass, progressObject));
    // maxValue?: number;
    RETURN_FALSE_IF_FALSE(CallSetterOptional(env, progressClass, progressObject, "maxValue",
        progress.GetMaxValue()));
    // currentValue?: number;
    RETURN_FALSE_IF_FALSE(CallSetterOptional(env, progressClass, progressObject, "currentValue",
        progress.GetCurrentValue()));
    // isPercentage?: boolean;
    RETURN_FALSE_IF_FALSE(CallSetter(env, progressClass, progressObject, "isPercentage",
        BoolToAniBoolean(progress.GetIsPercentage())));
    return true;
}

void UnWarpNotificationTime(ani_env *env, ani_object obj,
    NotificationTime &notificationTime)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_double initialTime = 0.0;
    if (GetPropertyDouble(env, obj, "version", isUndefined, initialTime) == ANI_OK
        && isUndefined == ANI_FALSE) {
        notificationTime.SetInitialTime(static_cast<int32_t>(initialTime));
    }

    bool isCountDown = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isCountDown", isUndefined, isCountDown)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsCountDown(isCountDown);
    }

    bool isPaused = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isPaused", isUndefined, isPaused)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsPaused(isPaused);
    }

    bool isInTitle = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isInTitle", isUndefined, isInTitle)
        && isUndefined == ANI_FALSE) {
        notificationTime.SetIsInTitle(isInTitle);
    }
}

bool WarpNotificationTime(ani_env *env, const NotificationTime &time, bool isInitialTimeExist, ani_object &timeObject)
{
    ani_class timeClass = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationTimeInner;", timeClass, timeObject));
    // initialTime?: number;
    if (isInitialTimeExist) {
        RETURN_FALSE_IF_FALSE(CallSetterOptional(env, timeClass, timeObject, "initialTime",
            time.GetInitialTime()));
    }
    // isCountDown?: boolean;
    RETURN_FALSE_IF_FALSE(CallSetter(env, timeClass, timeObject, "isCountDown",
        BoolToAniBoolean(time.GetIsCountDown())));
    // isPaused?: boolean;
    RETURN_FALSE_IF_FALSE(CallSetter(env, timeClass, timeObject, "isPaused",
        BoolToAniBoolean(time.GetIsPaused())));
    // isInTitle?: boolean;
    RETURN_FALSE_IF_FALSE(CallSetter(env, timeClass, timeObject, "isInTitle",
        BoolToAniBoolean(time.GetIsInTitle())));
    return true;
}

ani_status UnWarpNotificationIconButton(ani_env *env, ani_object obj,
    NotificationIconButton &iconButton)
{
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    std::string name = "";
    if((status = GetPropertyString(env, obj, "name", isUndefined, name)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    iconButton.SetName(name);

    ani_ref iconRef = {};
    if ((status = env->Object_GetPropertyByName_Ref(obj, "iconResource", &iconRef)) != ANI_OK) {
        return status;
    }
    ResourceManager::Resource resource;
    if(ANI_OK == UnwrapResource(env, static_cast<ani_object>(iconRef), resource)) {
        iconButton.SetIconResource(std::make_shared<ResourceManager::Resource>(resource));
    } else {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(iconRef));
        if (pixelMap == nullptr) {
            return ANI_INVALID_ARGS;
        }
        iconButton.SetIconImage(pixelMap);
    }

    std::string text = "";
    isUndefined = ANI_TRUE;
    if(GetPropertyString(env, obj, "text", isUndefined, text) == ANI_OK && isUndefined == ANI_FALSE) {
       iconButton.SetName(text);
    }

    bool hidePanel = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "hidePanel", isUndefined, hidePanel)
        && isUndefined == ANI_FALSE) {
        iconButton.SetHidePanel(hidePanel);
    }
    return status;
}

ani_status GetIconButtonArray(ani_env *env, 
    ani_object param, const char *name, std::vector<NotificationIconButton> &res)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_double length;

    if (((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK) || isUndefined == ANI_TRUE) {
        ANS_LOGI("get param failed, may be %{public}s : undefined", name);
        return ANI_INVALID_ARGS;
    }

    status = env->Object_GetPropertyByName_Double(static_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref buttonRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &buttonRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }

        NotificationIconButton button;
        if(UnWarpNotificationIconButton(env, static_cast<ani_object>(buttonRef), button) == ANI_OK) {
            res.push_back(button);
        }
    }
    return status;
}

void UnWarpNotificationLocalLiveViewButton(ani_env *env, ani_object obj,
    NotificationLocalLiveViewButton &button)
{
    std::vector<std::string> names = {};
    ani_boolean isUndefined = ANI_TRUE;
    if(GetStringArray(env, obj, "names", isUndefined, names) == ANI_OK && isUndefined == ANI_FALSE) {
        for(auto name: names) {
            button.addSingleButtonName(name);
        }
    }

    std::vector<std::shared_ptr<PixelMap>> icons = {};
    if(ANI_OK == GetPixelMapArray(env, obj, "icons", icons)) {
        for(auto icon: icons) {
            button.addSingleButtonIcon(icon);
        }
    }
    std::vector<ResourceManager::Resource> resources = {};
    if(ANI_OK == GetResourceArray(env, obj, "iconsResource", resources)) {
        for(auto res: resources) {
            std::shared_ptr<ResourceManager::Resource> pRes = std::make_shared<ResourceManager::Resource>(res);
            button.addSingleButtonIconResource(pRes);
        }
    }
}

bool WarpNotificationLocalLiveViewButton(ani_env *env, const NotificationLocalLiveViewButton &button, ani_object &buttonObject)
{
    ani_class buttonClass = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationButtonInner;", buttonClass, buttonObject));
    // names?: Array<string>;
    std::vector<std::string> names = button.GetAllButtonNames();
    ani_object namesObjectArray = GetAniStringArrayByVectorString(env, names);
    if (namesObjectArray == nullptr) {
        ANS_LOGE("namesObjectArray is nullptr");
        return false;
    }
    RETURN_FALSE_IF_FALSE(CallSetter(env, buttonClass, buttonObject, "names", namesObjectArray));
    // icons?: Array<image.PixelMap>;
    std::vector<std::shared_ptr<Media::PixelMap>> icons = button.GetAllButtonIcons();
    ani_object iconsObjectArray = GetAniArrayPixelMap(env, icons);
    if (iconsObjectArray == nullptr) {
        ANS_LOGE("iconsObjectArray is nullptr");
        return false;
    }
    RETURN_FALSE_IF_FALSE(CallSetter(env, buttonClass, buttonObject, "icons", iconsObjectArray));
    // iconsResource?: Array<Resource>;
    std::vector<std::shared_ptr<ResourceManager::Resource>> iconsResource = button.GetAllButtonIconResource();
    ani_object resourceObjectArray = GetAniArrayResource(env, iconsResource);
    if (resourceObjectArray == nullptr) {
        ANS_LOGE("resourceObjectArray is nullptr");
        return false;
    }
    return CallSetter(env, buttonClass, buttonObject, "iconsResource", resourceObjectArray);
}

void UnWarpNotificationCapsule(ani_env *env, ani_object obj, NotificationCapsule &capsule)
{
    ani_boolean isUndefined = ANI_TRUE;
    std::string title = "";
    if(GetPropertyString(env, obj, "title", isUndefined, title) == ANI_OK && isUndefined == ANI_FALSE) {
        capsule.SetTitle(title);
    }

    std::string backgroundColor = "";
    isUndefined = ANI_TRUE;
    if(GetPropertyString(env, obj, "backgroundColor", isUndefined, backgroundColor) == ANI_OK
        && isUndefined == ANI_FALSE) {
        capsule.SetBackgroundColor(backgroundColor);
    }

    std::string content = "";
    isUndefined = ANI_TRUE;
    if(GetPropertyString(env, obj, "content", isUndefined, content) == ANI_OK && isUndefined == ANI_FALSE) {
        capsule.SetContent(content);
    }

    ani_double time = 0.0;
    if(GetPropertyDouble(env, obj, "time", isUndefined, time) == ANI_OK && isUndefined == ANI_FALSE) {
       capsule.SetTime(static_cast<int32_t>(time));
    }

    ani_ref iconRef = {};
    if(GetPropertyRef(env, obj, "time", isUndefined, iconRef) == ANI_OK && isUndefined == ANI_FALSE) {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(iconRef));
        if (pixelMap != nullptr) {
            capsule.SetIcon(pixelMap);
        }
    }

    std::vector<NotificationIconButton> iconButtons = {};
    if (GetIconButtonArray(env, obj, "capsuleButtons", iconButtons) == ANI_OK && !(iconButtons.empty())) {
        capsule.SetCapsuleButton(iconButtons);
    }
}

ani_object WarpNotificationIconButton(ani_env *env, const NotificationIconButton &button)
{
    ani_class iconButtonCls = nullptr;
    ani_object iconButtonObject = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationIconButtonInner;", iconButtonCls, iconButtonObject));
    // name: string
    ani_string stringValue = nullptr;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, button.GetName(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, iconButtonCls, iconButtonObject, "name", stringValue));
    // text?: string;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, button.GetText(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, iconButtonCls, iconButtonObject, "text", stringValue));
    // hidePanel?: boolean;
    RETURN_NULL_IF_FALSE(CallSetter(
        env, iconButtonCls, iconButtonObject, "hidePanel", BoolToAniBoolean(button.GetHidePanel())));
    // iconResource: IconType;    type IconType = Resource | image.PixelMap;
    std::shared_ptr<Media::PixelMap> icon = button.GetIconImage();
    if (icon) {
        ani_object pixelMapObject = CreateAniPixelMap(env, icon);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("CreatePixelMap failed, pixelMapObject is nullptr");
            return nullptr;
        }
        RETURN_NULL_IF_FALSE(CallSetter(env, iconButtonCls, iconButtonObject, "iconResource", pixelMapObject));
    } else {
        ani_object resourceObject = GetAniResource(env, button.GetIconResource());
        if (resourceObject == nullptr) {
            ANS_LOGE("SetResourceObject failed, resourceObject is nullptr");
            return nullptr;
        }
        RETURN_NULL_IF_FALSE(CallSetter(env, iconButtonCls, iconButtonObject, "iconResource", resourceObject));
    }
    return iconButtonObject;
}

ani_object GetAniIconButtonArray(ani_env *env, const std::vector<NotificationIconButton> buttons)
{
    if (buttons.empty()) {
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env,buttons.size());
    ani_size index = 0;
    for (auto &button : buttons) {
        ani_object item = WarpNotificationIconButton(env, button);
        RETURN_NULL_IF_NULL(item);
        if(ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)){
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
            return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}

bool WarpNotificationCapsule(ani_env *env, const NotificationCapsule &capsule, ani_object &capsuleObject)
{
    ani_class capsuleClass = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationCapsuleInner;", capsuleClass, capsuleObject));
    // title?: string;
    ani_string stringValue = nullptr;
    if(GetAniStringByString(env, capsule.GetTitle(), stringValue)) {
         CallSetter(env, capsuleClass, capsuleObject, "title", stringValue);
    }
    // icon?: image.PixelMap;
    std::shared_ptr<Media::PixelMap> icon = capsule.GetIcon();
    if (icon) {
        ani_object pixelMapObject = CreateAniPixelMap(env, icon);
        if (pixelMapObject == nullptr) {
            ANS_LOGE("CreatePixelMap failed, pixelMapObject is nullptr");
        } else {
            CallSetter(env, capsuleClass, capsuleObject, "icon", pixelMapObject);
        }
    }
    // backgroundColor?: string;
    if(GetAniStringByString(env, capsule.GetBackgroundColor(), stringValue)) {
        CallSetter(env, capsuleClass, capsuleObject, "backgroundColor", stringValue);
    }
    //content?: string;
    if(GetAniStringByString(env, capsule.GetContent(), stringValue)) {
        CallSetter(env, capsuleClass, capsuleObject, "content", stringValue);
    }
    // time?: number;
    CallSetterOptional(env, capsuleClass, capsuleObject, "time", capsule.GetTime());
    // capsuleButtons?: Array<NotificationIconButton>;
    std::vector<NotificationIconButton> buttons = capsule.GetCapsuleButton();
    ani_object buttonsObjectArray = GetAniIconButtonArray(env, buttons);
    if (buttonsObjectArray != nullptr) {
        CallSetter(env, capsuleClass, capsuleObject, "capsuleButtons", buttonsObjectArray);
    }
    return true;
}

ani_status UnWarpNotificationBasicContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationBasicContent> basicContent)
{
    ANS_LOGI("UnWarpNotificationBasicContent call");
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    std::string title;
    if((status = GetPropertyString(env, obj, "title", isUndefined, title)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    basicContent->SetTitle(title);

    std::string text;
    isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "text", isUndefined, text)) != ANI_OK || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    basicContent->SetText(text);

    std::string additionalText;
    isUndefined = ANI_TRUE;
    if(GetPropertyString(env, obj, "additionalText", isUndefined, additionalText) == ANI_OK
        && isUndefined == ANI_FALSE) {
        basicContent->SetAdditionalText(additionalText);
    }

    ani_ref lockscreenPictureRef = {};
    if (env->Object_GetPropertyByName_Ref(obj, "lockscreenPicture", &lockscreenPictureRef)) {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(lockscreenPictureRef));
        if (pixelMap != nullptr) {
            basicContent->SetLockScreenPicture(pixelMap);
        }
    }
    return status;
}

ani_status UnWarpNotificationNormalContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationNormalContent> &normalContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, normalContent)) != ANI_OK) {
        return status;
    }
    return status;
}

ani_status UnWarpNotificationLongTextContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLongTextContent> &longTextContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, longTextContent)) != ANI_OK) {
        return status;
    }

    ani_boolean isUndefined = ANI_TRUE;
    std::string longText;
    if((status = GetPropertyString(env, obj, "longText", isUndefined, longText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetLongText(longText);

    std::string briefText;
    isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetBriefText(briefText);

    std::string expandedTitle;
    isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "expandedTitle", isUndefined, expandedTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    longTextContent->SetExpandedTitle(expandedTitle);

    return status;
}

ani_status UnWarpNotificationMultiLineContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationMultiLineContent> &multiLineContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, multiLineContent)) != ANI_OK) {
        return status;
    }

    ani_boolean isUndefined = ANI_TRUE;
    std::string longTitle;
    if((status = GetPropertyString(env, obj, "longTitle", isUndefined, longTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    multiLineContent->SetExpandedTitle(longTitle);

    std::string briefText;
    isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    multiLineContent->SetBriefText(briefText);

    std::vector<std::string> lines = {};
    isUndefined = ANI_TRUE;
    if((status = GetStringArray(env, obj, "lines", isUndefined, lines)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    for(auto line : lines) {
        multiLineContent->AddSingleLine(line);
    }
    return status;
}

ani_status UnWarpNotificationPictureContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationPictureContent> &pictureContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, pictureContent)) != ANI_OK) {
        return status;
    }

    std::string expandedTitle;
    ani_boolean isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "expandedTitle", isUndefined, expandedTitle)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetExpandedTitle(expandedTitle);

    std::string briefText;
    isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, obj, "briefText", isUndefined, briefText)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetBriefText(briefText);

    ani_ref pictureRef = {};
    if ((status = env->Object_GetPropertyByName_Ref(obj, "picture", &pictureRef)) != ANI_OK) {
        return status;
    }
    std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(pictureRef));
    if (pixelMap == nullptr) {
        return ANI_INVALID_ARGS;
    }
    pictureContent->SetBigPicture(pixelMap);

    return status;
}

ani_status UnWarpNotificationLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, liveViewContent)) != ANI_OK) {
        return status;
    }

    ani_ref statusRef;
    if((status = env->Object_GetPropertyByName_Ref(obj, "status", &statusRef)) != ANI_OK) {
        return status;
    }
    LiveViewStatus liveViewStatus = LiveViewStatus::LIVE_VIEW_CREATE;
    if(!LiveViewStatusEtsToC(env, static_cast<ani_enum_item>(statusRef), liveViewStatus)) {
        return ANI_INVALID_ARGS;
    }
    liveViewContent->SetLiveViewStatus(liveViewStatus);

    ani_double versionAni = 0.0;
    ani_boolean isUndefined = ANI_TRUE;
    if (GetPropertyDouble(env, obj, "version", isUndefined, versionAni) == ANI_OK
        && isUndefined == ANI_FALSE) {
        liveViewContent->SetVersion(static_cast<int32_t>(versionAni));
    }

    ani_ref extraInfoRef;
    isUndefined = ANI_TRUE;
    if (ANI_OK == (status = env->Object_GetPropertyByName_Ref(obj, "extraInfo", &extraInfoRef))
        && env->Reference_IsUndefined(extraInfoRef, &isUndefined) == ANI_OK && isUndefined == ANI_FALSE) {
        AAFwk::WantParams wantParams = {};
        if(UnwrapWantParams(env, extraInfoRef, wantParams)) {
            std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<WantParams>(wantParams);
            liveViewContent->SetExtraInfo(extraInfo);
        }
    }

    ani_ref pictureInfoRef;
    isUndefined = ANI_TRUE;
    if (ANI_OK == env->Object_GetPropertyByName_Ref(obj, "pictureInfo", &pictureInfoRef)
        && env->Reference_IsUndefined(pictureInfoRef, &isUndefined) == ANI_OK && isUndefined == ANI_FALSE) {
        std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap;
        if(GetMapOfPictureInfo(env, static_cast<ani_object>(pictureInfoRef), pictureMap) == ANI_OK) {
            liveViewContent->SetPicture(pictureMap);
        }
    }

    bool isLocalUpdateOnly = true;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isLocalUpdateOnly", isUndefined, isLocalUpdateOnly)
        && isUndefined == ANI_FALSE) {
        liveViewContent->SetIsOnlyLocalUpdate(isLocalUpdateOnly);
    }
    return status;
}

ani_status UnWarpNotificationLocalLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent)
{
    ani_status status =ANI_ERROR;
    if((status = UnWarpNotificationBasicContent(env, obj, localLiveViewContent)) != ANI_OK) {
        return status;
    }

    ani_double typeCode = 0.0;
    ani_boolean isUndefined = ANI_TRUE;
    if((status = GetPropertyDouble(env, obj, "typeCode", isUndefined, typeCode)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    localLiveViewContent->SetType(static_cast<int32_t>(typeCode));

    ani_ref capsuleRef = {};
    if(env->Object_GetPropertyByName_Ref(obj, "capsule", &capsuleRef) == ANI_OK) {
        NotificationCapsule capsule;
        UnWarpNotificationCapsule(env, static_cast<ani_object>(capsuleRef), capsule);
        localLiveViewContent->SetCapsule(capsule);
    }

    ani_ref buttonRef = {};
    if(env->Object_GetPropertyByName_Ref(obj, "button", &buttonRef) == ANI_OK) {
        NotificationLocalLiveViewButton button;
        UnWarpNotificationLocalLiveViewButton(env, static_cast<ani_object>(buttonRef), button);
        localLiveViewContent->SetButton(button);
    }

    std::vector<NotificationIconButton> buttons = {};
    if(GetIconButtonArray(env, obj, "cardButtons", buttons) == ANI_OK) {
        localLiveViewContent->SetCardButton(buttons);
    }

    ani_ref timeRef = {};
    if(env->Object_GetPropertyByName_Ref(obj, "time", &timeRef) == ANI_OK) {
        NotificationTime notificationTime;
        UnWarpNotificationTime(env, static_cast<ani_object>(timeRef), notificationTime);
        localLiveViewContent->SetTime(notificationTime);
    }

    ani_ref progressRef = {};
    if(env->Object_GetPropertyByName_Ref(obj, "progress", &progressRef) == ANI_OK) {
        NotificationProgress notificationProgress;
        UnWarpNotificationProgress(env, static_cast<ani_object>(progressRef), notificationProgress);
        localLiveViewContent->SetProgress(notificationProgress);
    }

    ani_ref liveViewTypeRef = {};
    if(env->Object_GetPropertyByName_Ref(obj, "liveViewType", &liveViewTypeRef) == ANI_OK) {
        LiveViewTypes liveViewTypes = LiveViewTypes::LIVE_VIEW_ACTIVITY;
        if(LiveViewTypesEtsToC(env, static_cast<ani_enum_item>(liveViewTypeRef), liveViewTypes)) {
            localLiveViewContent->SetLiveViewType(liveViewTypes);
        }
    }

    return status;
}

bool SetNotificationBasicContent(
    ani_env* env, ani_class contentCls, const NotificationBasicContent *basicContent, ani_object &object)
{
    ANS_LOGD("enter");
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return false;
    }
    ani_string aniStr;
    if(GetAniStringByString(env, basicContent->GetTitle(), aniStr)) {
        CallSetter(env, contentCls, object, "title", aniStr);
    }
    if(GetAniStringByString(env, basicContent->GetText(), aniStr)) {
        CallSetter(env, contentCls, object, "text", aniStr);
    }
    if(GetAniStringByString(env, basicContent->GetAdditionalText(), aniStr)) {
        CallSetter(env, contentCls, object, "additionalText", aniStr);
    }
    ani_object lockScreenPicObj = CreateAniPixelMap(env, basicContent->GetLockScreenPicture());
    if (lockScreenPicObj != nullptr) {
        CallSetter(env, contentCls, object, "lockScreenPicture", lockScreenPicObj);
    }
    return true;
}

bool SetNotificationNormalContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationBasicContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, basicContent.get(), contentObj));
    return CallSetter(env, ncCls, ncObj, "normal", contentObj);
}

bool SetNotificationLongTextContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("enter SetNotificationLongTextContent");
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationLongTextContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    NotificationLongTextContent *content = static_cast<NotificationLongTextContent *>(basicContent.get());
    if (content == nullptr) {
        ANS_LOGE("TextContent is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, content, contentObj));

    ani_string aniStr;
    if(GetAniStringByString(env, content->GetLongText(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "longText", aniStr);
    }
    if(GetAniStringByString(env, content->GetBriefText(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "briefText", aniStr);
    }
    if(GetAniStringByString(env, content->GetExpandedTitle(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "expandedTitle", aniStr);
    }
    return CallSetter(env, ncCls, ncObj, "longText", contentObj);
}

bool SetNotificationPictureContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("enter SetNotificationPictureContent");
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationPictureContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    NotificationPictureContent *content = static_cast<NotificationPictureContent *>(basicContent.get());
    if (content == nullptr) {
        ANS_LOGE("TextContent is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, content, contentObj));

    ani_string aniStr;
    if(GetAniStringByString(env, content->GetBriefText(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "briefText", aniStr);
    }
    if(GetAniStringByString(env, content->GetExpandedTitle(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "expandedTitle", aniStr);
    }
    ani_object pictureObj = CreateAniPixelMap(env, content->GetBigPicture());
    if (pictureObj != nullptr) {
        CallSetter(env, contentCls, contentObj, "picture", pictureObj);
    }
    return CallSetter(env, ncCls, ncObj, "picture", contentObj);
}

bool SetNotificationMultiLineContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("enter SetNotificationMultiLineContent");
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationMultiLineContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    NotificationMultiLineContent *content = static_cast<NotificationMultiLineContent *>(basicContent.get());
    if (content == nullptr) {
        ANS_LOGE("Content is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, content, contentObj));

    ani_string aniStr;
    if(GetAniStringByString(env, content->GetBriefText(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "briefText", aniStr);
    }
    if(GetAniStringByString(env, content->GetExpandedTitle(), aniStr)) {
        CallSetter(env, contentCls, contentObj, "longTitle", aniStr);
    }
    std::vector<std::string> allLines = content->GetAllLines();
    ani_object allLinesObject = GetAniStringArrayByVectorString(env, allLines);
    if(allLinesObject != nullptr) {
        CallSetter(env, contentCls, contentObj, "lines", allLinesObject);
    }
    ani_object lineWantAgentsObject = GetAniWantAgentArray(env, content->GetLineWantAgents());
    if(lineWantAgentsObject != nullptr) {
        CallSetter(env, contentCls, contentObj, "lineWantAgents", lineWantAgentsObject);
    }
    return CallSetter(env, ncCls, ncObj, "multiLine", contentObj);
}

bool SetNotificationLocalLiveViewContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("enter SetNotificationLocalLiveViewContent");
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationSystemLiveViewContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    NotificationLocalLiveViewContent *content = static_cast<NotificationLocalLiveViewContent *>(basicContent.get());
    if (content == nullptr) {
        ANS_LOGE("Content is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, content, contentObj));
    
    CallSetterOptional(env, contentCls, contentObj, "typeCode", content->GetType());

    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE)) {
        ani_object capsuleObject = nullptr;
        if(WarpNotificationCapsule(env, content->GetCapsule(), capsuleObject) && capsuleObject != nullptr) {
            CallSetter(env, contentCls, contentObj, "capsule", capsuleObject);
        }
    }
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON)) {
        ani_object buttonObject = nullptr;
        if(WarpNotificationLocalLiveViewButton(env, content->GetButton(), buttonObject) && buttonObject != nullptr) {
            CallSetter(env, contentCls, contentObj, "button", buttonObject);
        }
    }
    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CARD_BUTTON)) {
        std::vector<NotificationIconButton> buttons = content->GetCardButton();
        ani_object buttonsObjectArray = GetAniIconButtonArray(env, buttons);
        if (buttonsObjectArray != nullptr) {
            CallSetter(env, contentCls, contentObj, "cardButtons", buttonsObjectArray);
        }
    }

    ani_enum_item enumItem = nullptr;
    if (LiveViewTypesCToEts(env, content->GetLiveViewType(), enumItem) && enumItem != nullptr) {
        CallSetter(env, contentCls, contentObj, "liveViewType", enumItem);
    }

    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS)) {
        ani_object progressObject = nullptr;
        if (WarpNotificationProgress(env, content->GetProgress(), progressObject) && progressObject != nullptr) {
            CallSetter(env, contentCls, contentObj, "progress", progressObject);
        }
    }

    if (content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::TIME)) {
        bool flag = content->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
        ani_object timeObject = nullptr;
        if (WarpNotificationTime(env, content->GetTime(), flag, timeObject) && timeObject != nullptr) {
            CallSetter(env, contentCls, contentObj, "time", timeObject);
        }
    }
    return CallSetter(env, ncCls, ncObj, "systemLiveView", contentObj);
}

bool SetNotificationLiveViewContent(
    ani_env* env, ani_class ncCls, std::shared_ptr<NotificationContent> nContent, ani_object &ncObj)
{
    ANS_LOGD("enter SetNotificationLocalLiveViewContent");
    ani_class contentCls;
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
                "Lnotification/notificationContent/NotificationLiveViewContentInner;", contentCls, contentObj));
    RETURN_FALSE_IF_FALSE(contentCls != nullptr && contentObj != nullptr);
    std::shared_ptr<NotificationBasicContent> basicContent = nContent->GetNotificationContent();
    RETURN_FALSE_IF_NULL(basicContent);
    NotificationLiveViewContent *content = static_cast<NotificationLiveViewContent *>(basicContent.get());
    if (content == nullptr) {
        ANS_LOGE("Content is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(SetNotificationBasicContent(env, contentCls, content, contentObj));

    ani_object lockScreenPicObj = CreateAniPixelMap(env, content->GetLockScreenPicture());
    if (lockScreenPicObj != nullptr) {
        CallSetter(env, contentCls, contentObj, "lockScreenPicture", lockScreenPicObj);
    }
    ani_enum_item enumItem = nullptr;
    if(LiveViewStatusCToEts(env, content->GetLiveViewStatus(), enumItem) && enumItem != nullptr) {
        CallSetter(env, contentCls, contentObj, "status", enumItem);
    }
    CallSetterOptional(env, contentCls, contentObj, "version", static_cast<int32_t>(content->GetVersion()));
    std::shared_ptr<AAFwk::WantParams> extraInfoData = content->GetExtraInfo();
    if (extraInfoData != nullptr) {
        ani_ref extraInfoObj = WrapWantParams(env, *extraInfoData);
        if (extraInfoObj != nullptr) {
            CallSetter(env, contentCls, contentObj, "extraInfo", extraInfoObj);
        }
    }
    ani_object pictureInfoObj = nullptr;
    if (GetAniPictrueInfo(env, content->GetPicture(), pictureInfoObj) && pictureInfoObj != nullptr) {
        CallSetter(env, contentCls, contentObj, "pictureInfo", pictureInfoObj);
    }
    return CallSetter(env, ncCls, ncObj, "liveView", contentObj);
}

bool SetNotificationContent(ani_env* env, std::shared_ptr<NotificationContent> ncContent, ani_object &ncObj)
{
    ani_class ncCls;
    RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
        "Lnotification/notificationContent/NotificationContentInner;", ncCls, ncObj));
    // notificationContentType?: notificationManager.ContentType;
    ContentType contentType = ncContent->GetContentType();
    ani_enum_item contentTypeItem {};
    RETURN_FALSE_IF_FALSE(ContentTypeCToEts(env, contentType, contentTypeItem));
    RETURN_FALSE_IF_FALSE(CallSetter(env, ncCls, ncObj, "notificationContentType", contentTypeItem));
    switch (contentType) {
        case ContentType::BASIC_TEXT: // normal?: NotificationBasicContent
            return SetNotificationNormalContent(env, ncCls, ncContent, ncObj);
        case ContentType::LONG_TEXT: // longText?: NotificationLongTextContent
            return SetNotificationLongTextContent(env, ncCls, ncContent, ncObj);
        case ContentType::PICTURE: // picture?: NotificationPictureContent
            return SetNotificationPictureContent(env, ncCls, ncContent, ncObj);
        // need to do
        //case ContentType::CONVERSATION: // conversation?: NotificationConversationalContent
            //ret = SetNotificationConversationalContent(env, basicContent.get(), contentResult);
        //    break;
        case ContentType::MULTILINE: // multiLine?: NotificationMultiLineContent
            return SetNotificationMultiLineContent(env, ncCls, ncContent, ncObj);
        case ContentType::LOCAL_LIVE_VIEW: // systemLiveView?: NotificationLocalLiveViewContent
            return SetNotificationLocalLiveViewContent(env, ncCls, ncContent, ncObj);
            break;
        case ContentType::LIVE_VIEW: // liveView?: NotificationLiveViewContent
//            RETURN_FALSE_IF_FALSE(!CreateClassObjByClassName(env,
//                "Lnotification/notificationContent/NotificationLiveViewContentInner;", clsContent, aniContext));
//            RETURN_FALSE_IF_NULL(clsContent);
//            RETURN_FALSE_IF_NULL(aniContext);
//            RETURN_FALSE_IF_FALSE(SetNotificationLiveViewContent(env, clsContent, basicContent.get(), aniContext));
//            RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "liveView", aniContext));
            break;
        default:
            ANS_LOGE("ContentType is does not exist");
            return false;
    }
    return true;
}

} // namespace NotificationSts
} // OHOS
