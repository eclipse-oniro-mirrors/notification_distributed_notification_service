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
#include "sts_request.h"

#include "sts_common.h"
#include "sts_convert_other.h"
#include "sts_notification_flag.h"
#include "sts_notification_manager.h"
#include "sts_notification_content.h"
#include "sts_action_button.h"
#include "sts_bundle_option.h"
#include "sts_template.h" 
#include "want_params.h"
#include "ani_common_want.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

void UnWarpDistributedOptions(ani_env *env, ani_object obj, StsDistributedOptions distributedOptions)
{
    bool isDistributed = false;
    ani_boolean isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isDistributed", isUndefined, isDistributed)
        && isUndefined == ANI_FALSE) {
        distributedOptions.isDistributed = isDistributed;
    }

    std::vector<std::string> supportDisplayDevices = {};
    isUndefined = ANI_TRUE;
    if(GetStringArray(env, obj, "supportDisplayDevices", isUndefined, supportDisplayDevices) == ANI_OK
        && isUndefined == ANI_FALSE) {
        distributedOptions.supportDisplayDevices = supportDisplayDevices;
    }

    std::vector<std::string> supportOperateDevices = {};
    isUndefined = ANI_TRUE;
    if(GetStringArray(env, obj, "supportOperateDevices", isUndefined, supportOperateDevices) == ANI_OK
        && isUndefined == ANI_FALSE) {
        distributedOptions.supportOperateDevices = supportOperateDevices;
    }

    ani_double remindType = 0.0;
    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyDouble(env, obj, "remindType", isUndefined, remindType)
        && isUndefined == ANI_FALSE) {
        distributedOptions.remindType = static_cast<int32_t>(remindType);
    }
}

bool WarpNotificationUnifiedGroupInfo(ani_env* env,
    const std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo, ani_object &groupInfoObject)
{
    if (groupInfo == nullptr) {
        ANS_LOGE("groupInfo is null");
        return false;
    }
    ani_class groupInfoCls = nullptr;
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationRequest/UnifiedGroupInfoInner;", groupInfoCls, groupInfoObject));
    // key?: string;
    ani_string stringValue = nullptr;
    if (GetAniStringByString(env, groupInfo->GetKey(), stringValue)) {
        CallSetter(env, groupInfoCls, groupInfoObject, "key", stringValue);
    }
    // title?: string;
    if (GetAniStringByString(env, groupInfo->GetTitle(), stringValue)) {
        CallSetter(env, groupInfoCls, groupInfoObject, "title", stringValue);
    }
    // content?: string;
    if (GetAniStringByString(env, groupInfo->GetContent(), stringValue)) {
        CallSetter(env, groupInfoCls, groupInfoObject, "content", stringValue);
    }
    // sceneName?: string;
    if (GetAniStringByString(env, groupInfo->GetSceneName(), stringValue)) {
        CallSetter(env, groupInfoCls, groupInfoObject, "sceneName", stringValue);
    }
    // extraInfo?: Record<string, Object>;
    std::shared_ptr<AAFwk::WantParams> extraInfo = groupInfo->GetExtraInfo();
    if (extraInfo) {
        ani_ref valueRef = OHOS::AppExecFwk::WrapWantParams(env, *extraInfo);
        CallSetter(env, groupInfoCls, groupInfoObject, "extraInfo", valueRef);
    }
    return true;
}

void GetNotificationRequestByBooleanOne(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    bool mbool = false;
    ani_boolean isUndefined = ANI_TRUE;

    if(ANI_OK == GetPropertyBool(env, obj, "isOngoing", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetInProgress(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isUnremovable", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetUnremovable(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "updateOnly", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetUpdateOnly(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "tapDismissed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetTapDismissed(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "colorEnabled", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetColorEnabled(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isAlertOnce", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetAlertOneTime(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isStopwatch", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetShowStopwatch(mbool);
    }
}

void GetNotificationRequestByBooleanTwo(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    bool mbool = false;
    ani_boolean isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isCountDown", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetCountdownTimer(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isFloatingIcon", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetFloatingIcon(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "showDeliveryTime", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetShowDeliveryTime(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "isRemoveAllowed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetRemoveAllowed(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "forceDistributed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetForceDistributed(mbool);
    }

    isUndefined = ANI_TRUE;
    if(ANI_OK == GetPropertyBool(env, obj, "notDistributed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetNotDistributed(mbool);
    }
}

void GetNotificationRequestByBoolean(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    GetNotificationRequestByBooleanOne(env, obj, request);
    GetNotificationRequestByBooleanTwo(env, obj, request);
}

void GetNotificationRequestByString(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request) {
    std::string mString = "";
    ani_boolean isUndefined = ANI_TRUE;

    if (ANI_OK == GetPropertyString(env, obj, "classification", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetClassification(mString);
    }

    if (ANI_OK == GetPropertyString(env, obj, "appMessageId", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetAppMessageId(mString);
    }

    if (ANI_OK == GetPropertyString(env, obj, "label", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetLabel(mString);
    }

    if (ANI_OK == GetPropertyString(env, obj, "groupName", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetGroupName(mString);
    }

    if (ANI_OK == GetPropertyString(env, obj, "sound", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetSound(mString);
    }
}

void GetNotificationRequestByNumber(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request) {
    ani_double mDouble = 0.0;
    ani_boolean isUndefined = ANI_TRUE;

    if(ANI_OK == GetPropertyDouble(env, obj, "id", isUndefined, mDouble) && isUndefined == ANI_FALSE) {
        request->SetNotificationId(static_cast<int32_t>(mDouble));
    } else {
        request->SetNotificationId(0);
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "deliveryTime", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        request->SetDeliveryTime(static_cast<int32_t>(mDouble));
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "autoDeletedTime", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        request->SetAutoDeletedTime(static_cast<int32_t>(mDouble));
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "color", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        request->SetColor(static_cast<int32_t>(mDouble));
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "badgeIconStyle", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        int32_t style = static_cast<int32_t>(mDouble);
        request->SetBadgeIconStyle(static_cast<NotificationRequest::BadgeStyle>(style));
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "badgeNumber", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        request->SetBadgeNumber(static_cast<int32_t>(mDouble));
    }

    if(ANI_OK == GetPropertyDouble(env, obj, "notificationControlFlags", isUndefined, mDouble)
        && isUndefined == ANI_FALSE) {
        request->SetNotificationControlFlags(static_cast<int32_t>(mDouble));
    }
}

bool GetNotificationNormalContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "normal", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    UnWarpNotificationNormalContent(env, static_cast<ani_object>(contentRef), normalContent);
    request->SetContent(std::make_shared<NotificationContent>(normalContent));
    return true;
}

bool GetNotificationLongTextContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "longText", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationLongTextContent> longTextContent
        = std::make_shared<NotificationLongTextContent>();
    UnWarpNotificationLongTextContent(env, static_cast<ani_object>(contentRef), longTextContent);
    request->SetContent(std::make_shared<NotificationContent>(longTextContent));
    return true;
}

bool GetNotificationPictureContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "picture", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationPictureContent> pictureContent
        = std::make_shared<NotificationPictureContent>();
    UnWarpNotificationPictureContent(env, static_cast<ani_object>(contentRef), pictureContent);
    request->SetContent(std::make_shared<NotificationContent>(pictureContent));
    return true;
}

bool GetNotificationMultiLineContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "multiLine", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationMultiLineContent> multiLineContent
        = std::make_shared<NotificationMultiLineContent>();
    UnWarpNotificationMultiLineContent(env, static_cast<ani_object>(contentRef), multiLineContent);
    request->SetContent(std::make_shared<NotificationContent>(multiLineContent));
    return true;
}

bool GetNotificationLocalLiveViewContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "systemLiveView", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationLocalLiveViewContent> localLiveView 
        = std::make_shared<NotificationLocalLiveViewContent>();
    UnWarpNotificationLocalLiveViewContent(env, static_cast<ani_object>(contentRef), localLiveView);
    request->SetContent(std::make_shared<NotificationContent>(localLiveView));
    return true;
}

bool GetNotificationLiveViewContent(ani_env *env, ani_object obj, ani_ref contentRef,
    std::shared_ptr<NotificationRequest> &request)
{
    if(env->Object_GetPropertyByName_Ref(obj, "liveView", &contentRef) != ANI_OK) {
        return false;
    }
    std::shared_ptr<NotificationLiveViewContent> liveViewContent
        = std::make_shared<NotificationLiveViewContent>();
    UnWarpNotificationLiveViewContent(env, static_cast<ani_object>(contentRef), liveViewContent);
    request->SetContent(std::make_shared<NotificationContent>(liveViewContent));
    return true;
}

bool GetNotificationContent(ani_env *env, ani_object obj, ContentType outType,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_ref contentRef = {};
    switch (outType) {
        case ContentType::BASIC_TEXT:
            return GetNotificationNormalContent(env, obj, contentRef, request);
        case ContentType::LONG_TEXT:
            return GetNotificationLongTextContent(env, obj, contentRef, request);
        case ContentType::PICTURE:
            return GetNotificationPictureContent(env, obj, contentRef, request);
        case ContentType::MULTILINE:
            return GetNotificationMultiLineContent(env, obj, contentRef, request);
        case ContentType::LOCAL_LIVE_VIEW:
            return GetNotificationLocalLiveViewContent(env, obj, contentRef, request);
        case ContentType::LIVE_VIEW:
            return GetNotificationLiveViewContent(env, obj, contentRef, request);
        case ContentType::CONVERSATION:
            // need to add
            break;
        default:
            break;
    }
    return true;
}

ani_status GetNotificationContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref notificationContentRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "content", &notificationContentRef))!= ANI_OK) {
         return status;
    }
    ani_ref contentTypeRef;
    if((status = env->Object_GetPropertyByName_Ref(static_cast<ani_object>(notificationContentRef),
        "notificationContentType", &contentTypeRef)) != ANI_OK) {
        return status;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(contentTypeRef, &isUndefined)) != ANI_OK) {
         return status;
    }
    if (isUndefined == ANI_TRUE) {
        return ANI_INCORRECT_REF;
    }
    ContentType type;
    if(!ContentTypeEtsToC(env, static_cast<ani_enum_item>(contentTypeRef), type)) {
        return ANI_INVALID_ARGS;
    }

    if(!GetNotificationContent(env, static_cast<ani_object>(notificationContentRef), type, request)) {
        return ANI_INVALID_ARGS;
    }
    return status;
}

void GetNotificationSlotType(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref slotTypeRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "notificationSlotType", &slotTypeRef))!= ANI_OK) {
        return;
    }
    SlotType type = SlotType::OTHER;
    if(!SlotTypeEtsToC(env, static_cast<ani_enum_item>(slotTypeRef), type)) {
        return;
    }
    request->SetSlotType(type);
}

void GetNotificationWantAgent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref wantAgentRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "wantAgent", &wantAgentRef))!= ANI_OK) {
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef), reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
       return;
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    request->SetWantAgent(wantAgent);
}

void GetNotificationExtraInfo(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref extraInfoRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "extraInfo", &extraInfoRef))!= ANI_OK) {
        return;
    }
    ani_boolean isUndefind = ANI_TRUE;
    WantParams wantParams = {};
    if ((status = env->Reference_IsUndefined(extraInfoRef, &isUndefind)) == ANI_OK && isUndefind == ANI_FALSE) {
        UnwrapWantParams(env, extraInfoRef, wantParams);
        std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);
        request->SetAdditionalData(extras);
    }
}

void GetNotificationRemovalWantAgent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref wantAgentRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "removalWantAgent", &wantAgentRef))!= ANI_OK) {
        return;
    }
    WantAgent* pWantAgent = nullptr;
    UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef), reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
       return;
    }

    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    request->SetRemovalWantAgent(wantAgent);
}

void GetNotificationActionButtons(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    std::vector<std::shared_ptr<NotificationActionButton>> buttons = {};
    ani_status status = GetNotificationActionButtonArray(env, obj, "actionButtons", buttons);
    if (status == ANI_OK) {
        for(auto button: buttons) {
            request->AddActionButton(button);
        }
    }
}

void GetNotificationSmallIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref smallIconRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "smallIcon", &smallIconRef))!= ANI_OK) {
        return;
    }
    ani_boolean isUndefind = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(smallIconRef, &isUndefind)) == ANI_OK && isUndefind == ANI_FALSE) {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(smallIconRef));
        if (pixelMap != nullptr) {
            request->SetLittleIcon(pixelMap);
        }
    }
}

void GetNotificationLargeIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref largeIconRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "largeIcon", &largeIconRef))!= ANI_OK) {
        return;
    }
    ani_boolean isUndefind = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(largeIconRef, &isUndefind)) == ANI_OK && isUndefind == ANI_FALSE) {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(largeIconRef));
        if (pixelMap != nullptr) {
            request->SetBigIcon(pixelMap);
        }
    }
}

void GetNotificationOverlayIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref overlayIconRef = {};
    if((status = env->Object_GetPropertyByName_Ref(obj, "overlayIcon", &overlayIconRef))!= ANI_OK) {
        return;
    }
    ani_boolean isUndefind = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(overlayIconRef, &isUndefind)) == ANI_OK && isUndefind == ANI_FALSE) {
        std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(overlayIconRef));
        if (pixelMap != nullptr) {
            request->SetOverlayIcon(pixelMap);
        }
    }
}

void GetNotificationRequestDistributedOptions(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref optionRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "distributedOptionRef", isUndefind, optionRef);
    if (status == ANI_OK && isUndefind == ANI_FALSE) {
        StsDistributedOptions options;
        UnWarpDistributedOptions(env, static_cast<ani_object>(optionRef), options);
        request->SetDistributed(options.isDistributed);
        request->SetDevicesSupportDisplay(options.supportDisplayDevices);
        request->SetDevicesSupportOperate(options.supportOperateDevices);
    }
}

void GetNotificationTemplate(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref templateRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "template", isUndefind, templateRef);
    if (status == ANI_OK && isUndefind == ANI_FALSE) {
        OHOS::Notification::NotificationTemplate tmplate;
        UnwrapNotificationTemplate(env, static_cast<ani_object>(templateRef), tmplate);
        request->SetTemplate(std::make_shared<OHOS::Notification::NotificationTemplate>(tmplate));
    }
}

void GetNotificationUnifiedGroupInfo(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref infoRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "template", isUndefind, infoRef);
    if (status != ANI_OK || isUndefind == ANI_TRUE) {
        return;
    }

    std::shared_ptr<NotificationUnifiedGroupInfo> unifiedGroupInfo = std::make_shared<NotificationUnifiedGroupInfo>();
    std::string mString = "";
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "key", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetKey(mString);
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "title", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetTitle(mString);
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "content", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetContent(mString);
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "sceneName", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetSceneName(mString);
    }
    ani_ref extraInfoRef = {};
    status = GetPropertyRef(env, static_cast<ani_object>(infoRef), "extraInfo", isUndefind, extraInfoRef);
    if (status == ANI_OK && isUndefind == ANI_FALSE) {
        WantParams wantParams = {};
        UnwrapWantParams(env, extraInfoRef, wantParams);
        std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);
        unifiedGroupInfo->SetExtraInfo(extras);
    }
    request->SetUnifiedGroupInfo(unifiedGroupInfo);
}

void GetNotificationBundleOption(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref optionRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "representativeBundle", isUndefind, optionRef);
    if(status != ANI_OK || isUndefind == ANI_TRUE) {
        return;
    }
    OHOS::Notification::NotificationBundleOption option;
    if(ANI_OK == UnwrapBundleOption(env, static_cast<ani_object>(optionRef), option)) {
        request->SetBundleOption(std::make_shared<OHOS::Notification::NotificationBundleOption>(option));
    }
}

ani_status GetNotificationRequestByCustom(ani_env *env, ani_object obj,
    std::shared_ptr<OHOS::Notification::NotificationRequest> &notificationRequest)
{
    ani_status status = GetNotificationContent(env, obj, notificationRequest);
    if(status != ANI_OK) {
        return ANI_INVALID_ARGS;
    }

    GetNotificationSlotType(env, obj, notificationRequest);
    GetNotificationWantAgent(env, obj, notificationRequest);
    GetNotificationExtraInfo(env, obj, notificationRequest);
    GetNotificationRemovalWantAgent(env, obj, notificationRequest);
    GetNotificationActionButtons(env, obj, notificationRequest);
    GetNotificationSmallIcon(env, obj, notificationRequest);
    GetNotificationLargeIcon(env, obj, notificationRequest);
    GetNotificationOverlayIcon(env, obj, notificationRequest);
    GetNotificationRequestDistributedOptions(env, obj, notificationRequest);
    GetNotificationTemplate(env, obj, notificationRequest);
    GetNotificationUnifiedGroupInfo(env, obj, notificationRequest);
    GetNotificationBundleOption(env, obj, notificationRequest);
//    // need to do GetNotificationMaxScreenWantAgent  没看明白
//    /*
//    // maxScreenWantAgent?: WantAgent
//    if (GetNotificationMaxScreenWantAgent(env, value, request) == nullptr) {
//        return nullptr;
//    }
//    */

   return status;
}

ani_status UnWarpNotificationRequest(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &notificationRequest)
{
    ani_status status = ANI_ERROR;
    GetNotificationRequestByNumber(env, obj, notificationRequest);
    GetNotificationRequestByString(env, obj, notificationRequest);
    GetNotificationRequestByBoolean(env, obj, notificationRequest);
    status = GetNotificationRequestByCustom(env, obj, notificationRequest);
    return status;
}

bool SetNotificationRequestByBool(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // isOngoing?: boolean
    CallSetter(env, cls, object, "isOngoing", BoolToAniBoolean(request->IsInProgress()));
    // isUnremovable?: boolean
    CallSetter(env, cls, object, "isUnremovable", BoolToAniBoolean(request->IsUnremovable()));
    // tapDismissed?: boolean
    CallSetter(env, cls, object, "tapDismissed", BoolToAniBoolean(request->IsTapDismissed()));
    // colorEnabled?: boolean
    CallSetter(env, cls, object, "colorEnabled", BoolToAniBoolean(request->IsColorEnabled()));
    // isAlertOnce?: boolean
    CallSetter(env, cls, object, "isAlertOnce", BoolToAniBoolean(request->IsAlertOneTime()));
    // isStopwatch?: boolean
    CallSetter(env, cls, object, "isStopwatch", BoolToAniBoolean(request->IsShowStopwatch()));
    // isCountDown?: boolean
    CallSetter(env, cls, object, "isCountDown", BoolToAniBoolean(request->IsCountdownTimer()));
    // isFloatingIcon?: boolean
    CallSetter(env, cls, object, "isFloatingIcon", BoolToAniBoolean(request->IsFloatingIcon()));
    // showDeliveryTime?: boolean
    CallSetter(env, cls, object, "showDeliveryTime", BoolToAniBoolean(request->IsShowDeliveryTime()));
    // updateOnly?: boolean
    CallSetter(env, cls, object, "updateOnly", BoolToAniBoolean(request->IsUpdateOnly()));
    return true;
}

bool SetNotificationRequestByString(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    ani_string stringValue = nullptr;
    // classification?: string
    if (GetAniStringByString(env, request->GetClassification(), stringValue)) {
        CallSetter(env, cls, object, "classification", stringValue);
    }
    // need to do   ets中没有找到statusBarText属性
    // statusBarText?: string
    // if (StringToAniStr(env, request->GetStatusBarText(), stringValue)) {
    //     RETURN_FALSE_IF_FALSE(CallSetterOptional(env, cls, object, STATUS_BAR_TEXT, stringValue));
    // }
    // label?: string
    if (GetAniStringByString(env, request->GetLabel(), stringValue)) {
        CallSetter(env, cls, object, "label", stringValue);
    }
    // groupName?: string
    if (GetAniStringByString(env, request->GetGroupName(), stringValue)) {
        CallSetter(env, cls, object, "groupName", stringValue);
    }
    // readonly creatorBundleName?: string
    if (GetAniStringByString(env, request->GetCreatorBundleName(), stringValue)) {
        CallSetter(env, cls, object, "creatorBundleName", stringValue);
    }
    // readonly sound?: string
    if (GetAniStringByString(env, request->GetSound(), stringValue)) {
        CallSetter(env, cls, object, "sound", stringValue);
    }
    // readonly appInstanceKey?: string
    if (GetAniStringByString(env, request->GetAppInstanceKey(), stringValue)) {
        CallSetter(env, cls, object, "appInstanceKey", stringValue);
    }
    return true;
}

bool SetNotificationRequestByNumber(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // id?: number
    CallSetterOptional(env, cls, object, "id", request->GetNotificationId());
    // slotType?: SlotType
    ani_enum_item slotTypeItem {};
    if(SlotTypeCToEts(env, request->GetSlotType(), slotTypeItem)) {
        CallSetter(env, cls, object, "slotType", slotTypeItem);
    }
    
    // deliveryTime?: number
    CallSetterOptional(env, cls, object, "deliveryTime", request->GetDeliveryTime());
    // autoDeletedTime?: number
    CallSetterOptional(env, cls, object, "autoDeletedTime", request->GetAutoDeletedTime());
    // color ?: number
    CallSetterOptional(env, cls, object, "color", request->GetColor());
    // badgeIconStyle ?: number
    CallSetterOptional(env, cls, object, "badgeIconStyle",
        static_cast<int32_t>(request->GetBadgeIconStyle()));
    // readonly creatorUid?: number
    CallSetterOptional(env, cls, object, "creatorUid", request->GetCreatorUid());
    // readonly creatorPid?: number
    CallSetterOptional(env, cls, object, "creatorPid", request->GetCreatorPid());
    // badgeNumber?: number
    CallSetterOptional(env, cls, object, "badgeNumber", request->GetBadgeNumber());
    // readonly creatorInstanceKey?: number
    CallSetterOptional(env, cls, object, "creatorInstanceKey", request->GetCreatorInstanceKey());
    return true;
}

bool SetNotificationRequestByWantAgent(ani_env* env, ani_class cls,
    const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // wantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = request->GetWantAgent();
    if (agent) {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, agent.get());
        RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "wantAgent", wantAgent));
    } else {
        RETURN_FALSE_IF_FALSE(CallSetterNull(env, cls, object, "wantAgent"));
    }
    // removalWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> removalAgent = request->GetRemovalWantAgent();
    if (removalAgent) {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, removalAgent.get());
        RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "removalWantAgent", wantAgent));
    } else {
        RETURN_FALSE_IF_FALSE(CallSetterNull(env, cls, object, "removalWantAgent"));
    }
    // maxScreenWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> maxScreenAgent = request->GetMaxScreenWantAgent();
    if (maxScreenAgent) {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, maxScreenAgent.get());
        RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "maxScreenWantAgent", wantAgent));
    } else {
        RETURN_FALSE_IF_FALSE(CallSetterNull(env, cls, object, "maxScreenWantAgent"));
    }
    return true;
}

bool SetNotificationRequestByPixelMap(ani_env* env, ani_class cls, const NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // smallIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> littleIcon = request->GetLittleIcon();
    if (littleIcon) {
        ani_object smallIconResult = CreateAniPixelMap(env, littleIcon);
        if (smallIconResult == nullptr) {
            ANS_LOGE("CreatePixelMap failed,, smallIconResult is nullptr ");
            return false;
        }
        CallSetter(env, cls, object, "smallIcon", smallIconResult);
    }
    // largeIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> largeIcon = request->GetBigIcon();
    if (largeIcon) {
        ani_object largeIconResult = CreateAniPixelMap(env, largeIcon);
        if (largeIconResult == nullptr) {
            ANS_LOGE("CreatePixelMap failed, largeIconResult is nullptr");
            return false;
        }
        CallSetter(env, cls, object, "largeIcon", largeIconResult);
    }
    // overlayIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> overlayIcon = request->GetOverlayIcon();
    if (overlayIcon) {
        ani_object overlayIconResult = CreateAniPixelMap(env, overlayIcon);
        if (overlayIconResult == nullptr) {
            ANS_LOGE("CreatePixelMap failed, overlayIconResult is nullptr");
            return false;
        }
        CallSetter(env, cls, object, "overlayIcon", overlayIconResult);
    }
    return true;
}

bool SetNotificationRequestByNotificationContent(ani_env* env, ani_class cls,
    const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }

    std::shared_ptr<NotificationContent> content = request->GetContent();
    ani_object contentObj;
    RETURN_FALSE_IF_FALSE(SetNotificationContent(env, content, contentObj));
    RETURN_FALSE_IF_FALSE(contentObj == nullptr);
    RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "content", contentObj));
    return true;
}

bool SetNotificationRequestByCustom(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // content: NotificationContent
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByNotificationContent(env, cls, request, object));
    // extraInfo?: {[key:string] : any}
    std::shared_ptr<AAFwk::WantParams> additionalData = request->GetAdditionalData();
    if (additionalData) {
        ani_ref extraInfo = OHOS::AppExecFwk::WrapWantParams(env, *additionalData);
        RETURN_FALSE_IF_FALSE(CallSetterOptional(env, cls, object, "extraInfo", extraInfo));
    }

    // actionButtons?: Array<NotificationActionButton>
    std::vector<std::shared_ptr<NotificationActionButton>> actionButtons = request->GetActionButtons();
    ani_object actionButtonsArrayObj = GetAniArrayNotificationActionButton(env, actionButtons);
    if (actionButtonsArrayObj != nullptr) {
        RETURN_FALSE_IF_FALSE(CallSetterOptional(env, cls, object, "actionButtons", actionButtonsArrayObj));
    }
    // template?: NotificationTemplate
    std::shared_ptr<NotificationTemplate> templ = request->GetTemplate();
    if (templ) {
        ani_object templateObject = WrapNotificationTemplate(env, templ);
        if (templateObject != nullptr) {
            RETURN_FALSE_IF_FALSE(CallSetter(env, cls, object, "template", templateObject));
        }
    }
    // readonly notificationFlags?: NotificationFlags
     std::shared_ptr<NotificationFlags> flags = request->GetFlags();
    if (flags) {
        ani_object flagsObject = nullptr;
        if (WarpNotificationFlags(env, flags, flagsObject) && flagsObject != nullptr) {
            CallSetter(env, cls, object, "notificationFlags", flagsObject);
        }
    }
    // readonly agentBundle?: agentBundle
    std::shared_ptr<NotificationBundleOption> agentBundle = request->GetAgentBundle();
    if (agentBundle) {
        ani_object agentBundleObject = nullptr;
        if (WrapBundleOption(env, agentBundle, agentBundleObject) && agentBundleObject != nullptr) {
            CallSetter(env, cls, object, "agentBundle", agentBundleObject);
        }
    }
    // unifiedGroupInfo?: unifiedGroupInfo
    std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo = request->GetUnifiedGroupInfo();
    if (groupInfo) {
        ani_object infoObject = nullptr;
        if(WarpNotificationUnifiedGroupInfo(env, groupInfo, infoObject) && infoObject != nullptr) {
            CallSetter(env, cls, object, "unifiedGroupInfo", infoObject);
        }
    }
    return true;
}

bool WarpNotificationRequest(ani_env *env, const OHOS::Notification::NotificationRequest *notificationRequest,
    ani_class &cls, ani_object &outAniObj)
{
    if (notificationRequest == nullptr) {
        ANS_LOGE("notification is null");
        return false;
    }
    RETURN_FALSE_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationRequest/NotificationRequestInner;", cls, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByBool(env, cls, notificationRequest, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByString(env, cls, notificationRequest, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByNumber(env, cls, notificationRequest, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByWantAgent(env, cls, notificationRequest, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByPixelMap(env, cls, notificationRequest, outAniObj));
    RETURN_FALSE_IF_FALSE(SetNotificationRequestByCustom(env, cls, notificationRequest, outAniObj));
    return true;
}

ani_object GetAniNotificationRequestArray(ani_env *env, std::vector<sptr<NotificationRequest>> requests)
{
    if (requests.empty()) {
        ANS_LOGE("actionButtons is empty");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, requests.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &request : requests) {
        ani_class requestCls;
        ani_object requestObj;
        RETURN_NULL_IF_FALSE(WarpNotificationRequest(env, request.GetRefPtr(), requestCls, requestObj));
        RETURN_NULL_IF_NULL(requestObj);
        if(ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, requestObj)){
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
            return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}

ani_object GetAniNotificationRequestArrayByNotifocations(ani_env *env, std::vector<sptr<NotificationSts>> requests)
{
    if (requests.empty()) {
        ANS_LOGE("actionButtons is empty");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, requests.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &request : requests) {
        ani_class requestCls;
        ani_object requestObj;
        RETURN_NULL_IF_FALSE(WarpNotificationRequest(
            env, request->GetNotificationRequestPoint().GetRefPtr(), requestCls, requestObj));
        RETURN_NULL_IF_NULL(requestObj);
        if(ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, requestObj)){
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
            return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}
} // namespace NotificationSts
} // OHOS