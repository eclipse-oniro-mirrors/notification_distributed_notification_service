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
#include "ans_log_wrapper.h"
#include "want_params.h"
#include "ani_common_want.h"
#include "sts_bundle_option.h"
#include "sts_subscribe.h"
#include "sts_trigger.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

void UnWarpDistributedOptions(ani_env *env, ani_object obj, StsDistributedOptions &distributedOptions)
{
    ANS_LOGD("UnWarpDistributedOptions start");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpDistributedOptions failed, has nullptr");
        return;
    }
    // isDistributed?: boolean;
    bool isDistributed = false;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyBool(env, obj, "isDistributed", isUndefined, isDistributed)
        && isUndefined == ANI_FALSE) {
        distributedOptions.isDistributed = isDistributed;
    } else {
        ANS_LOGD("UnWarpDistributedOptions: isDistributed get failed");
    }
    // supportDisplayDevices?: Array<string>;
    std::vector<std::string> tempStrings = {};
    if (GetPropertyStringArray(env, obj, "supportDisplayDevices", tempStrings) == ANI_OK) {
        std::vector<std::string> supportDisplayDevices = {};
        for (auto device: tempStrings) {
            supportDisplayDevices.emplace_back(GetResizeStr(device, STR_MAX_SIZE));
        }
        distributedOptions.supportDisplayDevices = supportDisplayDevices;
    } else {
        ANS_LOGD("UnWarpDistributedOptions: supportDisplayDevices get failed");
    }
    // supportOperateDevices?: Array<string>;
    tempStrings.clear();
    if (GetPropertyStringArray(env, obj, "supportOperateDevices", tempStrings) == ANI_OK) {
        std::vector<std::string> supportOperateDevices = {};
        for (auto device: tempStrings) {
            supportOperateDevices.emplace_back(GetResizeStr(device, STR_MAX_SIZE));
        }
        distributedOptions.supportOperateDevices = supportOperateDevices;
    } else {
        ANS_LOGD("UnWarpDistributedOptions: supportOperateDevices get failed");
    }
    // readonly remindType?: int;
    ani_int remindType = 0;
    isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyInt(env, obj, "remindType", isUndefined, remindType)
        && isUndefined == ANI_FALSE) {
        distributedOptions.remindType = remindType;
    } else {
        ANS_LOGD("UnWarpDistributedOptions: remindType get failed");
    }
    ANS_LOGD("UnWarpDistributedOptions end");
}

bool WarpNotificationUnifiedGroupInfo(ani_env* env,
    const std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo, ani_object &groupInfoObject)
{
    ANS_LOGD("WarpNotificationUnifiedGroupInfo start");
    if (env == nullptr || groupInfo == nullptr) {
        ANS_LOGE("WarpNotificationUnifiedGroupInfo failed, has nullptr");
        return false;
    }
    ani_class groupInfoCls = nullptr;
    if ((!CreateClassObjByClassName(env,
        "notification.notificationRequest.UnifiedGroupInfoInner", groupInfoCls, groupInfoObject))
        || groupInfoCls == nullptr || groupInfoObject == nullptr) {
        ANS_LOGE("WarpNotificationUnifiedGroupInfo: create class failed");
        return false;
    }
    // key?: string;
    if (!groupInfo->GetKey().empty()
        && !SetPropertyOptionalByString(env, groupInfoObject, "key", groupInfo->GetKey())) {
            ANS_LOGE("WarpNotificationUnifiedGroupInfo: set key failed");
            return false;
        }
    // title?: string;
    if (!groupInfo->GetTitle().empty()
        && !SetPropertyOptionalByString(env, groupInfoObject, "title", groupInfo->GetTitle())) {
            ANS_LOGE("WarpNotificationUnifiedGroupInfo: set title failed");
            return false;
        }
    // content?: string;
    if (!groupInfo->GetContent().empty()
        && !SetPropertyOptionalByString(env, groupInfoObject, "content", groupInfo->GetContent())) {
            ANS_LOGE("WarpNotificationUnifiedGroupInfo: set content failed");
            return false;
        }
    // sceneName?: string;
    if (!groupInfo->GetSceneName().empty()
        && !SetPropertyOptionalByString(env, groupInfoObject, "sceneName", groupInfo->GetSceneName())) {
            ANS_LOGE("WarpNotificationUnifiedGroupInfo: set sceneName failed");
            return false;
        }
    // extraInfo?: Record<string, Object>;
    std::shared_ptr<AAFwk::WantParams> extraInfo = groupInfo->GetExtraInfo();
    if (extraInfo) {
        ani_ref valueRef = OHOS::AppExecFwk::WrapWantParams(env, *extraInfo);
        if (valueRef == nullptr) {
            ANS_LOGE("WrapWantParams faild. 'extraInfo'");
            return false;
        }
        if (!SetPropertyByRef(env, groupInfoObject, "extraInfo", valueRef)) {
            ANS_LOGE("WarpNotificationUnifiedGroupInfo: set extraInfo failed");
            return false;
        }
    }
    ANS_LOGD("WarpNotificationUnifiedGroupInfo end");
    return true;
}

void GetNotificationRequestByBooleanOne(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationRequestByBooleanOne start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationRequestByBooleanOne failed, has nullptr");
        return;
    }
    bool mbool = false;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyBool(env, obj, "isOngoing", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetInProgress(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "isUnremovable", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetUnremovable(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "updateOnly", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetUpdateOnly(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "tapDismissed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetTapDismissed(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "colorEnabled", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetColorEnabled(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "isAlertOnce", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetAlertOneTime(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "isStopwatch", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetShowStopwatch(mbool);
    }
    ANS_LOGD("GetNotificationRequestByBooleanOne end");
}

void GetNotificationRequestByBooleanTwo(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationRequestByBooleanTwo start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationRequestByBooleanTwo failed, has nullptr");
        return;
    }
    bool mbool = false;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyBool(env, obj, "isCountDown", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetCountdownTimer(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "isFloatingIcon", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetFloatingIcon(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "showDeliveryTime", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetShowDeliveryTime(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "isRemoveAllowed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetRemoveAllowed(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "forceDistributed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetForceDistributed(mbool);
    }
    if (ANI_OK == GetPropertyBool(env, obj, "notDistributed", isUndefined, mbool)
        && isUndefined == ANI_FALSE) {
        request->SetNotDistributed(mbool);
    }
    ANS_LOGD("GetNotificationRequestByBooleanTwo end");
}

void GetNotificationRequestByBoolean(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    GetNotificationRequestByBooleanOne(env, obj, request);
    GetNotificationRequestByBooleanTwo(env, obj, request);
}

void GetNotificationRequestByString(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationRequestByString start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationRequestByString failed, has nullptr");
        return;
    }
    std::string mString = "";
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyString(env, obj, "classification", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetClassification(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, obj, "appMessageId", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetAppMessageId(mString);
    }
    if (ANI_OK == GetPropertyString(env, obj, "label", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetLabel(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, obj, "groupName", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetGroupName(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, obj, "sound", isUndefined, mString) && isUndefined == ANI_FALSE) {
        request->SetSound(mString);
    }
    ANS_LOGD("GetNotificationRequestByString start");
}

void GetNotificationRequestByNumber(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationRequestByNumber start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationRequestByNumber failed, has nullptr");
        return;
    }
    ani_int mInt = 0;
    ani_long mLong = 0;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK == GetPropertyInt(env, obj, "id", isUndefined, mInt) && isUndefined == ANI_FALSE) {
        request->SetNotificationId(mInt);
    } else {
        request->SetNotificationId(0);
    }
    if (ANI_OK == GetPropertyLong(env, obj, "deliveryTime", isUndefined, mLong)
        && isUndefined == ANI_FALSE) {
        request->SetDeliveryTime(mLong);
    }
    if (ANI_OK == GetPropertyLong(env, obj, "autoDeletedTime", isUndefined, mLong)
        && isUndefined == ANI_FALSE) {
        request->SetAutoDeletedTime(mLong);
    }
    if (ANI_OK == GetPropertyLong(env, obj, "color", isUndefined, mLong)
        && isUndefined == ANI_FALSE) {
        request->SetColor(mLong);
    }
    if (ANI_OK == GetPropertyInt(env, obj, "badgeIconStyle", isUndefined, mInt)
        && isUndefined == ANI_FALSE) {
        request->SetBadgeIconStyle(static_cast<NotificationRequest::BadgeStyle>(mInt));
    }
    if (ANI_OK == GetPropertyLong(env, obj, "badgeNumber", isUndefined, mLong)
        && isUndefined == ANI_FALSE) {
        request->SetBadgeNumber(mLong);
    }
    if (ANI_OK == GetPropertyLong(env, obj, "notificationControlFlags", isUndefined, mLong)
        && isUndefined == ANI_FALSE) {
        request->SetNotificationControlFlags(static_cast<uint32_t>(mLong));
    }
    ANS_LOGD("GetNotificationRequestByNumber end");
}

int32_t GetNotificationNormalContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationNormalContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationNormalContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "normal", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationNormalContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    UnWarpNotificationNormalContent(env, static_cast<ani_object>(contentRef), normalContent);
    request->SetContent(std::make_shared<NotificationContent>(normalContent));
    ANS_LOGD("GetNotificationNormalContent end");
    return ERR_OK;
}

int32_t GetNotificationLongTextContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationLongTextContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationLongTextContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "longText", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationLongTextContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationLongTextContent> longTextContent
        = std::make_shared<NotificationLongTextContent>();
    UnWarpNotificationLongTextContent(env, static_cast<ani_object>(contentRef), longTextContent);
    request->SetContent(std::make_shared<NotificationContent>(longTextContent));
    ANS_LOGD("GetNotificationLongTextContent end");
    return ERR_OK;
}

int32_t GetNotificationPictureContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationPictureContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationPictureContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "picture", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationPictureContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationPictureContent> pictureContent
        = std::make_shared<NotificationPictureContent>();
    UnWarpNotificationPictureContent(env, static_cast<ani_object>(contentRef), pictureContent);
    request->SetContent(std::make_shared<NotificationContent>(pictureContent));
    ANS_LOGD("GetNotificationPictureContent end");
    return ERR_OK;
}

int32_t GetNotificationMultiLineContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationMultiLineContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationMultiLineContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "multiLine", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationMultiLineContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationMultiLineContent> multiLineContent
        = std::make_shared<NotificationMultiLineContent>();
    UnWarpNotificationMultiLineContent(env, static_cast<ani_object>(contentRef), multiLineContent);
    request->SetContent(std::make_shared<NotificationContent>(multiLineContent));
    ANS_LOGD("GetNotificationMultiLineContent end");
    return ERR_OK;
}

int32_t GetNotificationLocalLiveViewContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationLocalLiveViewContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationLocalLiveViewContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "systemLiveView", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationLocalLiveViewContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationLocalLiveViewContent> localLiveView
        = std::make_shared<NotificationLocalLiveViewContent>();
    ani_status status = ANI_OK;
    status = UnWarpNotificationLocalLiveViewContent(env, static_cast<ani_object>(contentRef), localLiveView);
    if (status != ANI_OK) {
        ANS_LOGE("UnWarpNotificationLocalLiveViewContent failed, status %{public}d", status);
        return ERROR_PARAM_INVALID;
    }
    request->SetContent(std::make_shared<NotificationContent>(localLiveView));
    ANS_LOGD("GetNotificationLocalLiveViewContent end");
    return ERR_OK;
}

int32_t GetNotificationLiveViewContent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationLiveViewContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationLiveViewContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref contentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "liveView", isUndefined, contentRef)
        || isUndefined == ANI_TRUE || contentRef == nullptr) {
        ANS_LOGE("GetNotificationLiveViewContent get ref failed");
        return ERROR_INTERNAL_ERROR;
    }
    std::shared_ptr<NotificationLiveViewContent> liveViewContent
        = std::make_shared<NotificationLiveViewContent>();
    UnWarpNotificationLiveViewContent(env, static_cast<ani_object>(contentRef), liveViewContent);
    request->SetContent(std::make_shared<NotificationContent>(liveViewContent));
    ANS_LOGD("GetNotificationLiveViewContent end");
    return ERR_OK;
}

int32_t GetNotificationContent(ani_env *env, ani_object obj, ContentType outType,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationContentWithType start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGD("GetNotificationContent ContentType = %{public}d", static_cast<int>(outType));
    switch (outType) {
        case ContentType::BASIC_TEXT:
            return GetNotificationNormalContent(env, obj, request);
        case ContentType::LONG_TEXT:
            return GetNotificationLongTextContent(env, obj, request);
        case ContentType::PICTURE:
            return GetNotificationPictureContent(env, obj, request);
        case ContentType::MULTILINE:
            return GetNotificationMultiLineContent(env, obj, request);
        case ContentType::LOCAL_LIVE_VIEW:
            return GetNotificationLocalLiveViewContent(env, obj, request);
        case ContentType::LIVE_VIEW:
            return GetNotificationLiveViewContent(env, obj, request);
        case ContentType::CONVERSATION:
            break;
        default:
            ANS_LOGD("ContentType not find. type %{public}d", static_cast<int32_t>(outType));
            break;
    }
    return ERR_OK;
}

int32_t GetNotificationContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationContent start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationContent failed, has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    ani_status status = ANI_OK;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref notificationContentRef = {};
    if (ANI_OK != (status = GetPropertyRef(env, obj, "content", isUndefined, notificationContentRef))
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetNotificationContent:get contentRef failed. status %{public}d", status);
        return ERROR_INTERNAL_ERROR;
    }
    ani_ref contentTypeRef;
    if (ANI_OK != (status = GetPropertyRef(env, static_cast<ani_object>(notificationContentRef),
        "notificationContentType", isUndefined, contentTypeRef))
        || isUndefined == ANI_TRUE || contentTypeRef == nullptr) {
        ANS_LOGE("GetNotificationContent:get notificationContentType failed. status %{public}d", status);
        return ERROR_INTERNAL_ERROR;
    }
    ContentType type;
    if (!ContentTypeEtsToC(env, static_cast<ani_enum_item>(contentTypeRef), type)) {
        ANS_LOGE("GetNotificationContent:ContentTypeEtsToC failed");
        return ERROR_INTERNAL_ERROR;
    }
    int32_t ret = GetNotificationContent(env, static_cast<ani_object>(notificationContentRef), type, request);
    if (ret != ERR_OK) {
        ANS_LOGE("GetNotificationContent:GetNotificationContent failed");
        return ret;
    }
    ANS_LOGD("GetNotificationContent end");
    return ERR_OK;
}

void GetNotificationSlotType(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ANS_LOGD("GetNotificationSlotType start");
    if (env == nullptr || obj == nullptr || request == nullptr) {
        ANS_LOGE("GetNotificationSlotType failed, has nullptr");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_OK;
    ani_ref slotTypeRef = {};
    if (ANI_OK != (status = GetPropertyRef(env, obj, "notificationSlotType", isUndefined, slotTypeRef))
        || isUndefined == ANI_TRUE || slotTypeRef == nullptr) {
            ANS_LOGE("GetNotificationSlotType: get Ref failed");
            return;
    }
    SlotType type = SlotType::OTHER;
    if (!SlotTypeEtsToC(env, static_cast<ani_enum_item>(slotTypeRef), type)) {
        ANS_LOGE("GetNotificationSlotType: SlotTypeEtsToC failed");
        return;
    }
    request->SetSlotType(type);
    ANS_LOGD("GetNotificationSlotType end");
}

void GetNotificationWantAgent(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref wantAgentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "wantAgent", isUndefined, wantAgentRef)
        || isUndefined == ANI_TRUE || wantAgentRef == nullptr) {
        ANS_LOGE("GetNotificationWantAgent: get ref failed");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef));
    if (wantAgent == nullptr) {
        ANS_LOGE("wantAgent is null");
        return;
    }
    request->SetWantAgent(wantAgent);
}

void GetNotificationExtraInfo(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref extraInfoRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "extraInfo", isUndefined, extraInfoRef)
        || isUndefined == ANI_TRUE || extraInfoRef == nullptr) {
        ANS_LOGE("GetNotificationExtraInfo: get ref failed");
        return;
    }
    WantParams wantParams = {};
    UnwrapWantParams(env, extraInfoRef, wantParams);
    std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);
    request->SetAdditionalData(extras);
}

void GetNotificationExtendInfo(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref extendInfoRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "extendInfo", isUndefined, extendInfoRef)
        || isUndefined == ANI_TRUE || extendInfoRef == nullptr) {
        ANS_LOGE("GetNotificationExtendInfo: get ref failed");
        return;
    }
    WantParams wantParams = {};
    UnwrapWantParams(env, extendInfoRef, wantParams);
    std::shared_ptr<WantParams> extends = std::make_shared<WantParams>(wantParams);
    request->SetExtendInfo(extends);
}

void GetNotificationRemovalWantAgent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref wantAgentRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "removalWantAgent", isUndefined, wantAgentRef)
        || isUndefined == ANI_TRUE || wantAgentRef == nullptr) {
        ANS_LOGE("GetNotificationRemovalWantAgent: get ref failed");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef));
    if (wantAgent == nullptr) {
        ANS_LOGE("wantAgent is null");
        return;
    }
    request->SetRemovalWantAgent(wantAgent);
}

void GetNotificationActionButtons(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    std::vector<std::shared_ptr<NotificationActionButton>> buttons = {};
    ani_status status = GetNotificationActionButtonArray(env, obj, "actionButtons", buttons);
    if (status == ANI_OK) {
        for (auto button : buttons) {
            request->AddActionButton(button);
        }
    }
}

void PictureScale(std::shared_ptr<Media::PixelMap> pixelMap)
{
    int32_t size = pixelMap->GetByteCount();
    if (size <= static_cast<int32_t>(MAX_ICON_SIZE)) {
        return;
    }
    int32_t width = pixelMap->GetWidth();
    int32_t height = pixelMap->GetHeight();
    float Axis = MAX_PIXEL_SIZE / std::max(width, height);
    pixelMap->scale(Axis, Axis, Media::AntiAliasingOption::HIGH);
}

void GetNotificationSmallIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref smallIconRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "smallIcon", isUndefined, smallIconRef)
        || isUndefined == ANI_TRUE || smallIconRef == nullptr) {
        ANS_LOGE("GetNotificationSmallIcon: get ref failed");
        return;
    }
    std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(smallIconRef));
    if (pixelMap != nullptr) {
        PictureScale(pixelMap);
        request->SetLittleIcon(pixelMap);
    }
}

void GetNotificationLargeIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref largeIconRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "largeIcon", isUndefined, largeIconRef)
        || isUndefined == ANI_TRUE || largeIconRef == nullptr) {
        ANS_LOGE("GetNotificationLargeIcon: get ref failed");
        return;
    }
    std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(largeIconRef));
    if (pixelMap != nullptr) {
        PictureScale(pixelMap);
        request->SetBigIcon(pixelMap);
    }
}

void GetNotificationOverlayIcon(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref overlayIconRef = {};
    if (ANI_OK != GetPropertyRef(env, obj, "overlayIcon", isUndefined, overlayIconRef)
        || isUndefined == ANI_TRUE || overlayIconRef == nullptr) {
        ANS_LOGE("GetNotificationOverlayIcon: get ref failed");
        return;
    }
    std::shared_ptr<PixelMap> pixelMap = GetPixelMapFromEnvSp(env, static_cast<ani_object>(overlayIconRef));
    if (pixelMap != nullptr) {
        PictureScale(pixelMap);
        request->SetOverlayIcon(pixelMap);
    }
}

void GetNotificationRequestDistributedOptions(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref optionRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "distributedOption", isUndefind, optionRef);
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
    status = GetPropertyRef(env, obj, "unifiedGroupInfo", isUndefind, infoRef);
    if (status != ANI_OK || isUndefind == ANI_TRUE) {
        return;
    }
    std::shared_ptr<NotificationUnifiedGroupInfo> unifiedGroupInfo = std::make_shared<NotificationUnifiedGroupInfo>();
    std::string mString = "";
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "key", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetKey(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "title", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetTitle(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "content", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetContent(GetResizeStr(mString, STR_MAX_SIZE));
    }
    if (ANI_OK == GetPropertyString(env, static_cast<ani_object>(infoRef), "sceneName", isUndefind, mString)
        && isUndefind == ANI_FALSE) {
        unifiedGroupInfo->SetSceneName(GetResizeStr(mString, STR_MAX_SIZE));
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
    if (status != ANI_OK || isUndefind == ANI_TRUE) {
        ANS_LOGE("Cannot get the value of representativeBundle. status %{public}d isUndefind %{public}d",
            status, isUndefind);
        return;
    }
    OHOS::Notification::NotificationBundleOption option;
    if (UnwrapBundleOption(env, static_cast<ani_object>(optionRef), option)) {
        request->SetBundleOption(std::make_shared<OHOS::Notification::NotificationBundleOption>(option));
    }
}

void GetNotificationTrigger(ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &request)
{
    ani_status status = ANI_ERROR;
    ani_ref triggerRef = {};
    ani_boolean isUndefind = ANI_TRUE;
    status = GetPropertyRef(env, obj, "trigger", isUndefind, triggerRef);
    if (status != ANI_OK || isUndefind == ANI_TRUE) {
        ANS_LOGE("Cannot get the value of trigger. status %{public}d isUndefind %{public}d",
            status, isUndefind);
        return;
    }
    OHOS::Notification::NotificationTrigger trigger;
    if (UnwrapTrigger(env, static_cast<ani_object>(triggerRef), trigger)) {
        request->SetNotificationTrigger(std::make_shared<OHOS::Notification::NotificationTrigger>(trigger));
    }
}

int32_t GetNotificationRequestByCustom(ani_env *env, ani_object obj,
    std::shared_ptr<OHOS::Notification::NotificationRequest> &notificationRequest)
{
    int32_t status = GetNotificationContent(env, obj, notificationRequest);
    if (status != ERR_OK) {
        return status;
    }
    GetNotificationSlotType(env, obj, notificationRequest);
    GetNotificationWantAgent(env, obj, notificationRequest);
    GetNotificationExtraInfo(env, obj, notificationRequest);
    GetNotificationExtendInfo(env, obj, notificationRequest);
    GetNotificationRemovalWantAgent(env, obj, notificationRequest);
    GetNotificationActionButtons(env, obj, notificationRequest);
    GetNotificationSmallIcon(env, obj, notificationRequest);
    GetNotificationLargeIcon(env, obj, notificationRequest);
    GetNotificationOverlayIcon(env, obj, notificationRequest);
    GetNotificationRequestDistributedOptions(env, obj, notificationRequest);
    GetNotificationTemplate(env, obj, notificationRequest);
    GetNotificationUnifiedGroupInfo(env, obj, notificationRequest);
    GetNotificationBundleOption(env, obj, notificationRequest);
    GetNotificationTrigger(env, obj, notificationRequest);
    return status;
}

int32_t UnWarpNotificationRequest(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationRequest> &notificationRequest)
{
    ANS_LOGD("UnWarpNotificationRequest start");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationRequest has nullptr");
        return ERROR_INTERNAL_ERROR;
    }
    int32_t status = ERR_OK;
    GetNotificationRequestByNumber(env, obj, notificationRequest);
    GetNotificationRequestByString(env, obj, notificationRequest);
    GetNotificationRequestByBoolean(env, obj, notificationRequest);
    status = GetNotificationRequestByCustom(env, obj, notificationRequest);
    ANS_LOGD("UnWarpNotificationRequest end");
    return status;
}

bool SetNotificationRequestByBool(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (env == nullptr || cls == nullptr || object == nullptr || request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // isOngoing?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isOngoing", request->IsInProgress())) {
        ANS_LOGD("SetNotificationRequest set 'isOngoing' faild");
    }
    // isUnremovable?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isUnremovable", request->IsUnremovable())) {
        ANS_LOGD("SetNotificationRequest set 'isUnremovable' faild");
    }
    // tapDismissed?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "tapDismissed", request->IsTapDismissed())) {
        ANS_LOGD("SetNotificationRequest set 'tapDismissed' faild");
    }
    // colorEnabled?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "colorEnabled", request->IsColorEnabled())) {
        ANS_LOGD("SetNotificationRequest set 'colorEnabled' faild");
    }
    // isAlertOnce?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isAlertOnce", request->IsAlertOneTime())) {
        ANS_LOGD("SetNotificationRequest set 'isAlertOnce' faild");
    }
    // isStopwatch?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isStopwatch", request->IsShowStopwatch())) {
        ANS_LOGD("SetNotificationRequest set 'isStopwatch' faild");
    }
    // isCountDown?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isCountDown", request->IsCountdownTimer())) {
        ANS_LOGD("SetNotificationRequest set 'isCountDown' faild");
    }
    // isFloatingIcon?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "isFloatingIcon", request->IsFloatingIcon())) {
        ANS_LOGD("SetNotificationRequest set 'isFloatingIcon' faild");
    }
    // showDeliveryTime?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "showDeliveryTime", request->IsShowDeliveryTime())) {
        ANS_LOGD("SetNotificationRequest set 'showDeliveryTime' faild");
    }
    // updateOnly?: boolean
    if (!SetPropertyOptionalByBoolean(env, object, "updateOnly", request->IsUpdateOnly())) {
        ANS_LOGD("SetNotificationRequest set 'updateOnly' faild");
    }
    return true;
}

bool SetNotificationRequestByString(ani_env* env, ani_class cls, const OHOS::Notification::NotificationRequest *request,
    ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // classification?: string
    std::string str = request->GetClassification();
    if (!SetPropertyOptionalByString(env, object, "classification", request->GetClassification())) {
        ANS_LOGD("SetNotificationRequest set '' faild");
    }
    // label?: string
    if (!SetPropertyOptionalByString(env, object, "label", request->GetLabel())) {
        ANS_LOGD("SetNotificationRequest set 'label' faild");
    }
    // groupName?: string
    if (!SetPropertyOptionalByString(env, object, "groupName", request->GetGroupName())) {
        ANS_LOGD("SetNotificationRequest set 'groupName' faild");
    }
    // readonly creatorBundleName?: string
    if (!SetPropertyOptionalByString(env, object, "creatorBundleName", request->GetCreatorBundleName())) {
        ANS_LOGD("SetNotificationRequest set 'creatorBundleName' faild");
    }
    // readonly sound?: string
    if (!SetPropertyOptionalByString(env, object, "sound", request->GetSound())) {
        ANS_LOGD("SetNotificationRequest set 'sound' faild");
    }
    // readonly appInstanceKey?: string
    if (!SetPropertyOptionalByString(env, object, "appInstanceKey", request->GetAppInstanceKey())) {
        ANS_LOGD("SetNotificationRequest set 'appInstanceKey' faild");
    }

    // readonly priorityNotificationType?: string
    if (!SetPropertyOptionalByString(env, object, "priorityNotificationType", request->GetPriorityNotificationType())) {
        ANS_LOGD("SetNotificationRequest set 'priorityNotificationType' faild");
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
    // id?: int
    SetPropertyOptionalByInt(env, object, "id", request->GetNotificationId());
    // slotType?: SlotType
    ani_enum_item slotTypeItem {};
    if (SlotTypeCToEts(env, request->GetSlotType(), slotTypeItem)) {
        CallSetter(env, cls, object, "notificationSlotType", slotTypeItem);
    }
    // deliveryTime?: long
    SetPropertyOptionalByLong(env, object, "deliveryTime", request->GetDeliveryTime());
    // autoDeletedTime?: long
    SetPropertyOptionalByLong(env, object, "autoDeletedTime", request->GetAutoDeletedTime());
    // color ?: long
    SetPropertyOptionalByLong(env, object, "color", request->GetColor());
    // badgeIconStyle ?: int
    SetPropertyOptionalByInt(env, object, "badgeIconStyle",
        static_cast<int32_t>(request->GetBadgeIconStyle()));
    // readonly creatorUid?: int
    SetPropertyOptionalByInt(env, object, "creatorUid", request->GetCreatorUid());
    // readonly creatorPid?: int
    SetPropertyOptionalByInt(env, object, "creatorPid", request->GetCreatorPid());
    // badgeNumber?: long
    SetPropertyOptionalByLong(env, object, "badgeNumber", request->GetBadgeNumber());
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
        if (wantAgent == nullptr || !SetPropertyByRef(env, object, "wantAgent", wantAgent)) {
            ANS_LOGD("SetNotificationRequest set 'wantAgent' faild");
        }
    }
    // removalWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> removalAgent = request->GetRemovalWantAgent();
    if (removalAgent) {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, removalAgent.get());
        if (wantAgent == nullptr || !SetPropertyByRef(env, object, "removalWantAgent", wantAgent)) {
            ANS_LOGD("SetNotificationRequest set 'removalWantAgent' faild");
        }
    }
    // maxScreenWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> maxScreenAgent = request->GetMaxScreenWantAgent();
    if (maxScreenAgent) {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, maxScreenAgent.get());
        if (wantAgent == nullptr || !SetPropertyByRef(env, object, "maxScreenWantAgent", wantAgent)) {
            ANS_LOGD("SetNotificationRequest set 'maxScreenWantAgent' faild");
        }
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
        if (smallIconResult == nullptr || !SetPropertyByRef(env, object, "smallIcon", smallIconResult)) {
            ANS_LOGD("SetNotificationRequest set 'smallIcon' faild");
        }
    }
    // largeIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> largeIcon = request->GetBigIcon();
    if (largeIcon) {
        ani_object largeIconResult = CreateAniPixelMap(env, largeIcon);
        if (largeIconResult == nullptr || !SetPropertyByRef(env, object, "largeIcon", largeIconResult)) {
            ANS_LOGD("SetNotificationRequest set 'largeIcon' faild");
        }
    }
    // overlayIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> overlayIcon = request->GetOverlayIcon();
    if (overlayIcon) {
        ani_object overlayIconResult = CreateAniPixelMap(env, overlayIcon);
        if (overlayIconResult == nullptr || !SetPropertyByRef(env, object, "overlayIcon", overlayIconResult)) {
            ANS_LOGD("SetNotificationRequest set 'overlayIcon' faild");
        }
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
    if (!SetNotificationContent(env, content, contentObj)) {
        ANS_LOGE("SetNotificationContent faild");
        return false;
    }
    if (contentObj == nullptr) {
        ANS_LOGE("contentObj is nullptr");
        return false;
    }
    if (!SetPropertyByRef(env, object, "content", contentObj)) {
        ANS_LOGE("SetNotificationRequestByNotificationContent. set content faild");
        return false;
    }
    return true;
}

bool SetRequestExtraInfo(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<AAFwk::WantParams> additionalData = request->GetAdditionalData();
    if (additionalData == nullptr) {
        ANS_LOGE("extraInfo is Undefine");
        return true;
    }
    ani_ref extraInfo = OHOS::AppExecFwk::WrapWantParams(env, *additionalData);
    if (extraInfo == nullptr || !SetPropertyByRef(env, object, "extraInfo", extraInfo)) {
        ANS_LOGD("SetNotificationRequestByCustom: set extraInfo failed");
    }
    return true;
}

bool SetRequestExtendInfo(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<AAFwk::WantParams> extendInfoData = request->GetExtendInfo();
    if (extendInfoData == nullptr) {
        ANS_LOGE("extendInfo is Undefine");
        return true;
    }
    ani_ref extendInfo = OHOS::AppExecFwk::WrapWantParams(env, *extendInfoData);
    if (extendInfo == nullptr || !SetPropertyByRef(env, object, "extendInfo", extendInfo)) {
        ANS_LOGD("SetNotificationRequestByCustom: set extendInfo failed");
    }
    return true;
}

bool SetRequestActionButtons(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::vector<std::shared_ptr<NotificationActionButton>> actionButtons = request->GetActionButtons();
    if (actionButtons.empty()) {
        ANS_LOGE("actionButtons is Undefine");
        return true;
    }
    ani_object actionButtonsArrayObj = GetAniArrayNotificationActionButton(env, actionButtons);
    if (actionButtonsArrayObj == nullptr
        || !SetPropertyByRef(env, object, "actionButtons", actionButtonsArrayObj)) {
        ANS_LOGD("SetNotificationRequest set 'actionButtons' faild");
    }
    return true;
}

bool SetRequestTemplate(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<NotificationTemplate> templ = request->GetTemplate();
    if (templ == nullptr) {
        ANS_LOGE("template is Undefine");
        return true;
    }
    ani_object templateObject = WrapNotificationTemplate(env, templ);
    if (templateObject == nullptr || !SetPropertyByRef(env, object, "template", templateObject)) {
        ANS_LOGD("SetNotificationRequest set 'template' faild");
    }
    return true;
}

bool SetRequestNotificationFlags(
    ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<NotificationFlags> flags = request->GetFlags();
    if (flags == nullptr) {
        ANS_LOGE("notificationFlags is Undefine");
        return true;
    }
    ani_object flagsObject = nullptr;
    if (!WarpNotificationFlags(env, flags, flagsObject) || flagsObject == nullptr) {
        ANS_LOGE("SetNotificationRequest Warp 'notificationFlags' faild");
        return false;
    }
    if (!SetPropertyByRef(env, object, "notificationFlags", flagsObject)) {
        ANS_LOGE("SetNotificationRequest set 'notificationFlags' faild");
        return false;
    }
    return true;
}

bool SetRequestAgentBundle(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<NotificationBundleOption> agentBundle = request->GetAgentBundle();
    if (agentBundle == nullptr) {
        ANS_LOGE("agentBundle is Undefine");
        return true;
    }
    ani_object agentBundleObject = nullptr;
    if (!WrapBundleOption(env, agentBundle, agentBundleObject) || agentBundleObject == nullptr) {
        ANS_LOGE("SetNotificationRequest Warp 'agentBundle' faild");
        return false;
    }
    if (!SetPropertyByRef(env, object, "agentBundle", agentBundleObject)) {
        ANS_LOGE("SetNotificationRequest set 'agentBundle' faild");
        return false;
    }
    return true;
}

bool SetRequestUnifiedGroupInfo(
    ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo = request->GetUnifiedGroupInfo();
    if (groupInfo == nullptr) {
        ANS_LOGE("unifiedGroupInfo is Undefine");
        return true;
    }
    ani_object infoObject = nullptr;
    if (!WarpNotificationUnifiedGroupInfo(env, groupInfo, infoObject) || infoObject == nullptr) {
        ANS_LOGD("SetNotificationRequest Warp 'unifiedGroupInfo' faild");
    }
    if (!SetPropertyByRef(env, object, "unifiedGroupInfo", infoObject)) {
        ANS_LOGD("SetNotificationRequest set 'unifiedGroupInfo' faild");
    }
    return true;
}

bool SetRequestTrigger(ani_env *env, const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    std::shared_ptr<NotificationTrigger> trigger = request->GetNotificationTrigger();
    if (trigger == nullptr) {
        ANS_LOGE("trigger is Undefine");
        return true;
    }
    ani_object triggerObject = nullptr;
    if (!WrapTrigger(env, trigger, triggerObject) || triggerObject == nullptr) {
        ANS_LOGD("SetNotificationRequest Warp 'trigger' faild");
    }
    if (!SetPropertyByRef(env, object, "trigger", triggerObject)) {
        ANS_LOGD("SetNotificationRequest set 'trigger' faild");
    }
    return true;
}

bool SetNotificationRequestByCustom(ani_env* env, ani_class cls,
    const OHOS::Notification::NotificationRequest *request, ani_object &object)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    // content: NotificationContent
    if (!SetNotificationRequestByNotificationContent(env, cls, request, object)) {
        ANS_LOGE("SetNotificationRequestByCustom: set content failed");
        return false;
    }
    // extraInfo?: Record<string, Object>
    if (!SetRequestExtraInfo(env, request, object)) {
        ANS_LOGE("set extraInfo faild");
    }
    // extendInfo?: Record<string, Object>
    if (!SetRequestExtendInfo(env, request, object)) {
        ANS_LOGE("set extendInfo faild");
    }
    // actionButtons?: Array<NotificationActionButton>
    if (!SetRequestActionButtons(env, request, object)) {
        ANS_LOGD("set actionButtons faild");
    }
    // template?: NotificationTemplate
    if (!SetRequestTemplate(env, request, object)) {
        ANS_LOGD("set template faild");
    }
    // readonly notificationFlags?: NotificationFlags
    if (!SetRequestNotificationFlags(env, request, object)) {
        ANS_LOGD("set notificationFlags faild");
    }
    // readonly agentBundle?: agentBundle
    if (!SetRequestAgentBundle(env, request, object)) {
        ANS_LOGD("set agentBundle faild");
    }
    // unifiedGroupInfo?: unifiedGroupInfo
    if (!SetRequestUnifiedGroupInfo(env, request, object)) {
        ANS_LOGD("set unifiedGroupInfo faild");
    }
    // trigger?: Trigger
    if (!SetRequestTrigger(env, request, object)) {
        ANS_LOGD("set trigger faild");
    }
    return true;
}

bool WarpNotificationRequest(ani_env *env, const OHOS::Notification::NotificationRequest *notificationRequest,
    ani_class &cls, ani_object &outAniObj)
{
    ANS_LOGD("WarpNotificationRequest start");
    if (notificationRequest == nullptr) {
        ANS_LOGE("notification is null");
        return false;
    }
    if (!CreateClassObjByClassName(env,
        "notification.notificationRequest.NotificationRequestInner", cls, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: create class failed");
        return false;
    }
    if (!SetNotificationRequestByBool(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set bools failed");
        return false;
    }
    if (!SetNotificationRequestByString(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set strings failed");
        return false;
    }
    if (!SetNotificationRequestByNumber(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set numbers failed");
        return false;
    }
    if (!SetNotificationRequestByWantAgent(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set WantAgent failed");
        return false;
    }
    if (!SetNotificationRequestByPixelMap(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set PixelMap failed");
        return false;
    }
    if (!SetNotificationRequestByCustom(env, cls, notificationRequest, outAniObj)) {
        ANS_LOGE("WarpNotificationRequest: set Customs failed");
        return false;
    }
    ANS_LOGD("WarpNotificationRequest end");
    return true;
}

bool SetNotificationRequestDistributedOptions(ani_env *env,
    const sptr<NotificationSts> notification, ani_object &object)
{
    ANS_LOGD("SetNotificationRequestDistributedOptions call");
    ani_object optionsObj;
    ani_class ncCls;
    if (!CreateClassObjByClassName(env, "notification.notificationRequest.DistributedOptionsInner",
        ncCls, optionsObj) || optionsObj == nullptr) {
        ANS_LOGE("create distributedOption class failed");
        return false;
    }
    NotificationDistributedOptions options = notification->GetNotificationRequest().GetNotificationDistributedOptions();
    // isDistributed?: boolean
    if (!SetPropertyOptionalByBoolean(env, optionsObj, "isDistributed", options.IsDistributed())) {
        ANS_LOGD("set isDistributed failed");
    }
    // supportDisplayDevices?: Array<string>
    ani_object displayDevices = GetAniStringArrayByVectorString(env, options.GetDevicesSupportDisplay());
    if (displayDevices == nullptr || !SetPropertyByRef(env, optionsObj, "supportDisplayDevices", displayDevices)) {
        ANS_LOGD("set supportDisplayDevices failed");
    }
    // supportOperateDevices?: Array<string>
    ani_object supportOperateDevices = GetAniStringArrayByVectorString(env, options.GetDevicesSupportOperate());
    if (supportOperateDevices == nullptr ||
        !SetPropertyByRef(env, optionsObj, "supportOperateDevices", supportOperateDevices)) {
        ANS_LOGD("set supportOperateDevices failed");
    }
    // readonly remindType?: number
    ani_enum_item remindTypeItem {};
    if (DeviceRemindTypeCToEts(env, notification->GetRemindType(), remindTypeItem)) {
        CallSetter(env, ncCls, optionsObj, "remindType", remindTypeItem);
    }
    if (!SetPropertyByRef(env, object, "distributedOption", optionsObj)) {
        ANS_LOGD("set distributedOption faild");
    }
    ANS_LOGD("SetNotificationRequestDistributedOptions end");
    return true;
}

bool WarpNotificationOther(ani_env *env, ani_class &cls,
    const sptr<NotificationSts> notification, ani_object &outAniObj)
{
    // hashCode?: string
    if (!SetPropertyOptionalByString(env, outAniObj, "hashCode", notification->GetKey().c_str())) {
        ANS_LOGD("set hashCode faild");
    }
    // isFloatingIcon ?: boolean
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "isFloatingIcon", notification->IsFloatingIcon())) {
        ANS_LOGD("set isFloatingIcon faild");
    }
    // readonly creatorBundleName?: string
    if (!SetPropertyOptionalByString(env, outAniObj, "creatorBundleName", notification->GetBundleName().c_str())) {
        ANS_LOGD("set creatorBundleName faild");
    }
    // readonly creatorUid?: number
    if (!SetPropertyOptionalByInt(env, outAniObj, "creatorUid", notification->GetNotificationRequest().GetOwnerUid())) {
        ANS_LOGD("set creatorUid faild");
    }
    // readonly creatorUserId?: number
    if (!SetPropertyOptionalByInt(env, outAniObj, "creatorUserId", notification->GetRecvUserId())) {
        ANS_LOGD("set creatorUserId faild");
    }
    // readonly creatorPid?: number
    if (!SetPropertyOptionalByInt(env, outAniObj, "creatorPid", notification->GetPid())) {
        ANS_LOGD("set creatorPid faild");
    }
    // distributedOption?:DistributedOptions
    if (!SetNotificationRequestDistributedOptions(env, notification, outAniObj)) {
        ANS_LOGE("set distributedOption faild");
        return false;
    }
    // readonly isRemoveAllowed?: boolean
    if (!SetPropertyOptionalByBoolean(env, outAniObj, "isRemoveAllowed", notification->IsRemoveAllowed())) {
        ANS_LOGD("set isRemoveAllowed faild");
    }
    // readonly source?: number
    ani_enum_item sourceTypeItem {};
    if (SourceTypeCToEts(env, notification->GetSourceType(), sourceTypeItem)) {
        CallSetter(env, cls, outAniObj, "source", sourceTypeItem);
    }
    // readonly deviceId?: string
    if (!SetPropertyOptionalByString(env, outAniObj, "deviceId", notification->GetDeviceId().c_str())) {
        ANS_LOGD("set deviceId faild");
    }
    // notificationControlFlags?: number
    if (!SetPropertyOptionalByLong(env, outAniObj, "notificationControlFlags",
        static_cast<long>(notification->GetNotificationRequest().GetNotificationControlFlags()))) {
        ANS_LOGD("set notificationControlFlags faild");
    }
    return true;
}

bool WarpNotification(ani_env *env, const sptr<NotificationSts> notification, ani_class &cls, ani_object &outAniObj)
{
    ANS_LOGD("WarpNotification called");
    if (notification == nullptr) {
        ANS_LOGE("null notification");
        return false;
    }
    NotificationRequest request = notification->GetNotificationRequest();
    if (!WarpNotificationRequest(env, &request, cls, outAniObj)) {
        return false;
    }
    if (!WarpNotificationOther(env, cls, notification, outAniObj)) {
        return false;
    }
    ANS_LOGD("WarpNotification end");
    return true;
}

ani_array GetAniNotificationRequestArray(ani_env *env, std::vector<sptr<NotificationRequest>> requests)
{
    ani_array arrayObj = newArrayClass(env, requests.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &request : requests) {
        ani_class requestCls;
        ani_object requestObj;
        if (!WarpNotificationRequest(env, request.GetRefPtr(), requestCls, requestObj) || requestObj == nullptr) {
            ANS_LOGE("WarpNotificationRequest faild. index %{public}d", index);
            return nullptr;
        }
        if (ANI_OK != env->Array_Set(arrayObj, index, requestObj)) {
            ANS_LOGE("Array_Set faild. index  %{public}d", index);
            return nullptr;
        }
        index ++;
    }
    return arrayObj;
}

ani_array GetAniNotificationRequestArrayByNotifocations(ani_env *env, std::vector<sptr<NotificationSts>> requests)
{
    ani_array arrayObj = newArrayClass(env, requests.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &request : requests) {
        ani_class requestCls;
        ani_object requestObj;
        if (!WarpNotificationRequest(
            env, request->GetNotificationRequestPoint().GetRefPtr(), requestCls, requestObj)
            || requestObj == nullptr) {
                ANS_LOGE("WarpNotificationRequest faild. index %{public}d", index);
                return nullptr;
            }
        if (ANI_OK
            != env->Array_Set(arrayObj, index, requestObj)) {
            ANS_LOGE("Array_Set faild. index  %{public}d", index);
            return nullptr;
        }
        index ++;
    }
    return arrayObj;
}

bool GetCheckRequestContent(ani_env *env, ani_object obj, NotificationContent::Type &outContentType)
{
    ani_status status = ANI_OK;
    ani_ref contentAniType;
    STSContentType contentType = NOTIFICATION_CONTENT_BASIC_TEXT;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(obj, "contentType", &contentAniType))) {
        ANS_LOGE("GetCheckRequestContent get contentType faild. status %{public}d", status);
        return false;
    }
    if (contentAniType == nullptr ||
        !EnumConvertAniToNative(env, static_cast<ani_enum_item>(contentAniType), contentType)) {
            ANS_LOGE("EnumConvertAniToNative contentType faild");
            return false;
        }
    if (!StsContentTypeUtils::StsToC(contentType, outContentType)) {
        ANS_LOGE("StsToC contentType faild");
        return false;
    }
    return true;
}

bool GetCheckRequestSlotType(ani_env *env, ani_object obj, NotificationConstant::SlotType &outSlotType)
{
    ani_status status = ANI_OK;
    ani_ref slotAniType;
    STSSlotType slotType = UNKNOWN_TYPE;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(obj, "slotType", &slotAniType))) {
        ANS_LOGE("UnWarpNotificationCheckRequest get slotType faild. status %{public}d", status);
        return false;
    }
    if (slotAniType == nullptr || !EnumConvertAniToNative(env, static_cast<ani_enum_item>(slotAniType), slotType)) {
        ANS_LOGE("EnumConvertAniToNative slotType faild");
        return false;
    }
    if (!StsSlotTypeUtils::StsToC(slotType, outSlotType)) {
        ANS_LOGE("StsToC slotType faild");
        return false;
    }
    return true;
}

bool UnWarpNotificationCheckRequest(ani_env *env, ani_object obj, sptr<NotificationCheckRequest> &checkRequest)
{
    if (env == nullptr || obj == nullptr || checkRequest == nullptr) {
        ANS_LOGE("UnWarpNotificationCheckRequest invalid parameters");
        return false;
    }
    ani_status status = ANI_OK;
    ani_ref extraInfoKeysObj;
    NotificationContent::Type outContentType = NotificationContent::Type::NONE;
    NotificationConstant::SlotType outSlotType = NotificationConstant::SlotType::OTHER;
    std::vector<std::string> extraInfoKeys;
    // contentType: notificationManager.ContentType;
    if (!GetCheckRequestContent(env, obj, outContentType)) {
        ANS_LOGE("GetCheckRequestContent faild.");
        return false;
    }
    checkRequest->SetContentType(outContentType);
    // slotType: notificationManager.SlotType;
    if (!GetCheckRequestSlotType(env, obj, outSlotType)) {
        ANS_LOGE("GetCheckRequestSlotType faild.");
        return false;
    }
    checkRequest->SetSlotType(outSlotType);
    // extraInfoKeys: Array<string>;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(obj, "extraInfoKeys", &extraInfoKeysObj))) {
        ANS_LOGE("UnWarpNotificationCheckRequest get extraInfoKeys faild. status %{public}d", status);
        return false;
    }
    if (!GetStringArrayByAniObj(env, static_cast<ani_object>(extraInfoKeysObj), extraInfoKeys)) {
        ANS_LOGE("UnWarpNotificationCheckRequest. extraInfoKeys GetStringArrayByAniObj faild.");
        return false;
    }
    checkRequest->SetExtraKeys(extraInfoKeys);
    ANS_LOGD("contentType %{public}d slotType %{public}d",
        checkRequest->GetContentType(), checkRequest->GetSlotType());
    for (auto &it : checkRequest->GetExtraKeys()) {
        ANS_LOGD("extrakey %{public}s", it.c_str());
    }
    return true;
}

bool UnWarpNotificationFilter(ani_env *env, ani_object obj, LiveViewFilter& filter)
{
    ANS_LOGD("UnWarpNotificationFilter call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnWarpNotificationFilter failed, has nullptr");
        return false;
    }

    ani_status status = ANI_OK;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref bundleObj = {};
    if (ANI_OK != (status = GetPropertyRef(env, obj, "bundle", isUndefined, bundleObj))
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationFilter:get bundle failed. status %{public}d", status);
        return false;
    }
    if (!OHOS::NotificationSts::UnwrapBundleOption(env, static_cast<ani_object>(bundleObj), filter.bundle)) {
        ANS_LOGE("UnWarpNotificationFilter:UnwrapBundleOption failed");
        return false;
    }

    ani_ref notificationKeyObj = {};
    if (ANI_OK != (status = GetPropertyRef(env, obj, "notificationKey", isUndefined, notificationKeyObj))
        || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationFilter:get notificationKey failed. status %{public}d", status);
        return false;
    }

    if (OHOS::NotificationSts::UnWarpNotificationKey(env, static_cast<ani_object>(notificationKeyObj),
        filter.notificationKey)) {
        ANS_LOGD("UnWarpNotificationFilter:UnWarpNotificationKey label is undefined");
    }

    if (ANI_OK != (status = GetPropertyStringArray(env, obj, "extraInfoKeys", filter.extraInfoKeys))) {
        ANS_LOGD("UnWarpNotificationFilter:get extraInfoKeysObj failed. status %{public}d", status);
    }
    return true;
}
} // namespace NotificationSts
} // OHOS