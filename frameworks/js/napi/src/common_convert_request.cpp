/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "common.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_action_button.h"
#include "notification_capsule.h"
#include "notification_constant.h"
#include "notification_local_live_view_content.h"
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
napi_value Common::SetNotificationRequestByString(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }

    // classification?: string
    napi_create_string_utf8(env, request->GetClassification().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "classification", value);

    // statusBarText?: string
    napi_create_string_utf8(env, request->GetStatusBarText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "statusBarText", value);

    // label?: string
    napi_create_string_utf8(env, request->GetLabel().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "label", value);

    // groupName?: string
    napi_create_string_utf8(env, request->GetGroupName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "groupName", value);

    // readonly creatorBundleName?: string
    napi_create_string_utf8(env, request->GetCreatorBundleName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "creatorBundleName", value);

    // readonly sound?: string
    napi_create_string_utf8(env, request->GetSound().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "sound", value);

    // readonly appInstanceKey?: string
    napi_create_string_utf8(env, request->GetAppInstanceKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "appInstanceKey", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequestByNumber(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }

    // id?: number
    napi_create_int32(env, request->GetNotificationId(), &value);
    napi_set_named_property(env, result, "id", value);

    // slotType?: SlotType
    SlotType outType = SlotType::UNKNOWN_TYPE;
    if (!AnsEnumUtil::SlotTypeCToJS(request->GetSlotType(), outType)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "slotType", value);
    napi_set_named_property(env, result, "notificationSlotType", value);

    // deliveryTime?: number
    napi_create_int64(env, request->GetDeliveryTime(), &value);
    napi_set_named_property(env, result, "deliveryTime", value);

    // autoDeletedTime?: number
    napi_create_int64(env, request->GetAutoDeletedTime(), &value);
    napi_set_named_property(env, result, "autoDeletedTime", value);

    // color ?: number
    napi_create_uint32(env, request->GetColor(), &value);
    napi_set_named_property(env, result, "color", value);

    // badgeIconStyle ?: number
    auto badgeIconStyle = static_cast<int32_t>(request->GetBadgeIconStyle());
    napi_create_int32(env, badgeIconStyle, &value);
    napi_set_named_property(env, result, "badgeIconStyle", value);

    // readonly creatorUid?: number
    napi_create_int32(env, request->GetCreatorUid(), &value);
    napi_set_named_property(env, result, "creatorUid", value);

    // readonly creatorPid?: number
    napi_create_int32(env, request->GetCreatorPid(), &value);
    napi_set_named_property(env, result, "creatorPid", value);

    // badgeNumber?: number
    napi_create_uint32(env, request->GetBadgeNumber(), &value);
    napi_set_named_property(env, result, "badgeNumber", value);

    // readonly creatorInstanceKey?: number
    napi_create_int32(env, request->GetCreatorInstanceKey(), &value);
    napi_set_named_property(env, result, "creatorInstanceKey", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequestByBool(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }
    // isOngoing?: boolean
    napi_get_boolean(env, request->IsInProgress(), &value);
    napi_set_named_property(env, result, "isOngoing", value);

    // isUnremovable?: boolean
    napi_get_boolean(env, request->IsUnremovable(), &value);
    napi_set_named_property(env, result, "isUnremovable", value);

    // tapDismissed?: boolean
    napi_get_boolean(env, request->IsTapDismissed(), &value);
    napi_set_named_property(env, result, "tapDismissed", value);

    // colorEnabled?: boolean
    napi_get_boolean(env, request->IsColorEnabled(), &value);
    napi_set_named_property(env, result, "colorEnabled", value);

    // isAlertOnce?: boolean
    napi_get_boolean(env, request->IsAlertOneTime(), &value);
    napi_set_named_property(env, result, "isAlertOnce", value);

    // isStopwatch?: boolean
    napi_get_boolean(env, request->IsShowStopwatch(), &value);
    napi_set_named_property(env, result, "isStopwatch", value);

    // isCountDown?: boolean
    napi_get_boolean(env, request->IsCountdownTimer(), &value);
    napi_set_named_property(env, result, "isCountDown", value);

    // isFloatingIcon?: boolean
    napi_get_boolean(env, request->IsFloatingIcon(), &value);
    napi_set_named_property(env, result, "isFloatingIcon", value);

    // showDeliveryTime?: boolean
    napi_get_boolean(env, request->IsShowDeliveryTime(), &value);
    napi_set_named_property(env, result, "showDeliveryTime", value);

    // UpdateOnly?: boolean
    napi_get_boolean(env, request->IsUpdateOnly(), &value);
    napi_set_named_property(env, result, "updateOnly", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequestByWantAgent(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }
    // wantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = request->GetWantAgent();
    if (agent) {
        napi_value wantAgent = nullptr;
        wantAgent = CreateWantAgentByJS(env, agent);
        napi_set_named_property(env, result, "wantAgent", wantAgent);
    } else {
        napi_set_named_property(env, result, "wantAgent", NapiGetNull(env));
    }

    // removalWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> removalAgent = request->GetRemovalWantAgent();
    if (removalAgent) {
        napi_value wantAgent = nullptr;
        wantAgent = CreateWantAgentByJS(env, removalAgent);
        napi_set_named_property(env, result, "removalWantAgent", wantAgent);
    } else {
        napi_set_named_property(env, result, "removalWantAgent", NapiGetNull(env));
    }

    // maxScreenWantAgent?: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> maxScreenAgent = request->GetMaxScreenWantAgent();
    if (maxScreenAgent) {
        napi_value wantAgent = nullptr;
        wantAgent = CreateWantAgentByJS(env, maxScreenAgent);
        napi_set_named_property(env, result, "maxScreenWantAgent", wantAgent);
    } else {
        napi_set_named_property(env, result, "maxScreenWantAgent", NapiGetNull(env));
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequestByPixelMap(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }

    // smallIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> littleIcon = request->GetLittleIcon();
    if (littleIcon) {
        napi_value smallIconResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        smallIconResult = Media::PixelMapNapi::CreatePixelMap(env, littleIcon);
        NAPI_CALL(env, napi_typeof(env, smallIconResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGE("smallIconResult is undefined");
            napi_set_named_property(env, result, "smallIcon", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "smallIcon", smallIconResult);
        }
    }

    // largeIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> largeIcon = request->GetBigIcon();
    if (largeIcon) {
        napi_value largeIconResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        largeIconResult = Media::PixelMapNapi::CreatePixelMap(env, largeIcon);
        NAPI_CALL(env, napi_typeof(env, largeIconResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGE("largeIconResult is undefined");
            napi_set_named_property(env, result, "largeIcon", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "largeIcon", largeIconResult);
        }
    }

    // overlayIcon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> overlayIcon = request->GetOverlayIcon();
    if (overlayIcon) {
        napi_value overlayIconResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        overlayIconResult = Media::PixelMapNapi::CreatePixelMap(env, overlayIcon);
        NAPI_CALL(env, napi_typeof(env, overlayIconResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGE("overlayIconResult is undefined");
            napi_set_named_property(env, result, "overlayIcon", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "overlayIcon", overlayIconResult);
        }
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequestByCustom(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }

    // content: NotificationContent
    std::shared_ptr<NotificationContent> content = request->GetContent();
    if (content) {
        napi_value contentResult = nullptr;
        napi_create_object(env, &contentResult);
        if (!SetNotificationContent(env, content, contentResult)) {
            ANS_LOGE("SetNotificationContent call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "content", contentResult);
    } else {
        ANS_LOGE("content is nullptr");
        return NapiGetBoolean(env, false);
    }

    // extraInfo?: {[key:string] : any}
    std::shared_ptr<AAFwk::WantParams> additionalData = request->GetAdditionalData();
    if (additionalData) {
        napi_value extraInfo = nullptr;
        extraInfo = OHOS::AppExecFwk::WrapWantParams(env, *additionalData);
        napi_set_named_property(env, result, "extraInfo", extraInfo);
    }

    // actionButtons?: Array<NotificationActionButton>
    napi_value arr = nullptr;
    uint32_t count = 0;
    napi_create_array(env, &arr);
    for (auto vec : request->GetActionButtons()) {
        if (vec) {
            napi_value actionButtonResult = nullptr;
            napi_create_object(env, &actionButtonResult);
            if (SetNotificationActionButton(env, vec, actionButtonResult)) {
                napi_set_element(env, arr, count, actionButtonResult);
                count++;
            }
        }
    }
    if (count != 0) {
        napi_set_named_property(env, result, "actionButtons", arr);
    }

    // template?: NotificationTemplate
    std::shared_ptr<NotificationTemplate> templ = request->GetTemplate();
    if (templ) {
        napi_value templateResult = nullptr;
        napi_create_object(env, &templateResult);
        if (!SetNotificationTemplateInfo(env, templ, templateResult)) {
            ANS_LOGE("SetNotificationTemplate call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "template", templateResult);
    }

    // readonly notificationFlags?: NotificationFlags
    std::shared_ptr<NotificationFlags> flags = request->GetFlags();
    if (flags) {
        napi_value flagsResult = nullptr;
        napi_create_object(env, &flagsResult);
        if (!SetNotificationFlags(env, flags, flagsResult)) {
            ANS_LOGE("SetNotificationFlags call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "notificationFlags", flagsResult);
    }

    // readonly agentBundle?: agentBundle
    std::shared_ptr<NotificationBundleOption> agentBundle = request->GetAgentBundle();
    if (agentBundle) {
        napi_value agentBundleResult = nullptr;
        napi_create_object(env, &agentBundleResult);
        if (!SetAgentBundle(env, agentBundle, agentBundleResult)) {
            ANS_LOGE("SetAgentBundle call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "agentBundle", agentBundleResult);
    }

    // unifiedGroupInfo?: unifiedGroupInfo
    std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo = request->GetUnifiedGroupInfo();
    if (groupInfo) {
        napi_value groupInfoResult = nullptr;
        napi_create_object(env, &groupInfoResult);
        if (!SetNotificationUnifiedGroupInfo(env, groupInfo, groupInfoResult)) {
            ANS_LOGE("SetNotificationUnifiedGroupInfo call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "unifiedGroupInfo", groupInfoResult);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationActionButton(
    const napi_env &env, const std::shared_ptr<NotificationActionButton> &actionButton, napi_value &result)
{
    ANS_LOGD("enter");
    if (actionButton == nullptr) {
        ANS_LOGE("actionButton is null");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;

    // title: string
    napi_create_string_utf8(env, actionButton->GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "title", value);

    // wantAgent: WantAgent
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = actionButton->GetWantAgent();
    if (agent == nullptr) {
        ANS_LOGE("wantAgent is null");
        napi_set_named_property(env, result, "wantAgent", NapiGetNull(env));
        return NapiGetBoolean(env, false);
    } else {
        napi_value wantAgent = nullptr;
        wantAgent = CreateWantAgentByJS(env, agent);
        napi_set_named_property(env, result, "wantAgent", wantAgent);
    }

    // icon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> icon = actionButton->GetIcon();
    if (icon) {
        napi_value iconResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        iconResult = Media::PixelMapNapi::CreatePixelMap(env, icon);
        NAPI_CALL(env, napi_typeof(env, iconResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGE("icon result is undefined");
            napi_set_named_property(env, result, "icon", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "icon", iconResult);
        }
    }

    if (!SetNotificationActionButtonByExtras(env, actionButton, result)) {
        return NapiGetBoolean(env, false);
    }

    // userInput?: NotificationUserInput
    napi_value userInputResult = nullptr;
    napi_create_object(env, &userInputResult);
    if (!SetNotificationActionButtonByUserInput(env, actionButton->GetUserInput(), userInputResult)) {
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "userInput", userInputResult);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationActionButtonByExtras(
    const napi_env &env, const std::shared_ptr<NotificationActionButton> &actionButton, napi_value &result)
{
    ANS_LOGD("enter");
    if (!actionButton) {
        ANS_LOGE("actionButton is null");
        return NapiGetBoolean(env, false);
    }
    // extras?: {[key: string]: any}
    auto extras = actionButton->GetAdditionalData();
    if (extras) {
        napi_value nExtras = nullptr;
        nExtras = OHOS::AppExecFwk::WrapWantParams(env, *extras);
        napi_set_named_property(env, result, "extras", nExtras);
    }
    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationActionButtonByUserInput(
    const napi_env &env, const std::shared_ptr<NotificationUserInput> &userInput, napi_value &result)
{
    ANS_LOGD("enter");

    if (!userInput) {
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;
    napi_value arr = nullptr;
    int count = 0;

    // inputKey: string
    napi_create_string_utf8(env, userInput->GetInputKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "inputKey", value);

    // tag: string
    napi_create_string_utf8(env, userInput->GetTag().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "tag", value);

    // options: Array<string>
    napi_create_array(env, &arr);
    for (auto vec : userInput->GetOptions()) {
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, arr, count, value);
        count++;
    }
    if (count > 0) {
        napi_set_named_property(env, result, "options", arr);
    }

    // permitFreeFormInput?: boolean
    napi_get_boolean(env, userInput->IsPermitFreeFormInput(), &value);
    napi_set_named_property(env, result, "permitFreeFormInput", value);

    // permitMimeTypes?: Array<string>
    count = 0;
    napi_create_array(env, &arr);
    for (auto vec : userInput->GetPermitMimeTypes()) {
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, arr, count, value);
        count++;
    }
    if (count > 0) {
        napi_set_named_property(env, result, "permitMimeTypes", arr);
    }

    // editType?: number
    napi_create_int64(env, userInput->GetEditType(), &value);
    napi_set_named_property(env, result, "editType", value);

    // additionalData?: {[key: string]: Object}
    auto additionalData = userInput->GetAdditionalData();
    if (additionalData) {
        napi_value nAdditionalData = nullptr;
        nAdditionalData = OHOS::AppExecFwk::WrapWantParams(env, *additionalData);
        napi_set_named_property(env, result, "additionalData", nAdditionalData);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationRequest(
    const napi_env &env, const OHOS::Notification::NotificationRequest *request, napi_value &result)
{
    ANS_LOGD("enter");

    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationRequestByString(env, request, result)) {
        return NapiGetBoolean(env, false);
    }
    if (!SetNotificationRequestByNumber(env, request, result)) {
        return NapiGetBoolean(env, false);
    }
    if (!SetNotificationRequestByBool(env, request, result)) {
        return NapiGetBoolean(env, false);
    }
    if (!SetNotificationRequestByWantAgent(env, request, result)) {
        return NapiGetBoolean(env, false);
    }
    if (!SetNotificationRequestByPixelMap(env, request, result)) {
        return NapiGetBoolean(env, false);
    }
    if (!SetNotificationRequestByCustom(env, request, result)) {
        return NapiGetBoolean(env, false);
    }

    return NapiGetBoolean(env, true);
}


napi_value Common::GetNotificationRequestByNumber(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    // id?: number
    if (GetNotificationId(env, value, request) == nullptr) {
        return nullptr;
    }
    // deliveryTime?: number
    if (GetNotificationDeliveryTime(env, value, request) == nullptr) {
        return nullptr;
    }
    // autoDeletedTime?: number
    if (GetNotificationAutoDeletedTime(env, value, request) == nullptr) {
        return nullptr;
    }
    // color?: number
    if (GetNotificationColor(env, value, request) == nullptr) {
        return nullptr;
    }
    // badgeIconStyle?: number
    if (GetNotificationBadgeIconStyle(env, value, request) == nullptr) {
        return nullptr;
    }
    // badgeNumber?: number
    if (GetNotificationBadgeNumber(env, value, request) == nullptr) {
        return nullptr;
    }
    // notificationControlFlags?: number
    if (GetNotificationControlFlags(env, value, request) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationRequestByString(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    // classification?: string
    if (GetNotificationClassification(env, value, request) == nullptr) {
        return nullptr;
    }
    // statusBarText?: string
    if (GetNotificationStatusBarText(env, value, request) == nullptr) {
        return nullptr;
    }
    // label?: string
    if (GetNotificationLabel(env, value, request) == nullptr) {
        return nullptr;
    }
    // groupName?: string
    if (GetNotificationGroupName(env, value, request) == nullptr) {
        return nullptr;
    }
    // appMessageId?: string
    if (GetNotificationAppMessageId(env, value, request) == nullptr) {
        return nullptr;
    }
    // sound?: string
    if (GetNotificationSound(env, value, request) == nullptr) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationRequestByBool(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    // isOngoing?: boolean
    if (GetNotificationIsOngoing(env, value, request) == nullptr) {
        return nullptr;
    }
    // isUnremovable?: boolean
    if (GetNotificationIsUnremovable(env, value, request) == nullptr) {
        return nullptr;
    }
    // tapDismissed?: boolean
    if (GetNotificationtapDismissed(env, value, request) == nullptr) {
        return nullptr;
    }
    // colorEnabled?: boolean
    if (GetNotificationColorEnabled(env, value, request) == nullptr) {
        return nullptr;
    }
    // isAlertOnce?: boolean
    if (GetNotificationIsAlertOnce(env, value, request) == nullptr) {
        return nullptr;
    }
    // isStopwatch?: boolean
    if (GetNotificationIsStopwatch(env, value, request) == nullptr) {
        return nullptr;
    }
    // isCountDown?: boolean
    if (GetNotificationIsCountDown(env, value, request) == nullptr) {
        return nullptr;
    }
    // showDeliveryTime?: boolean
    if (GetNotificationShowDeliveryTime(env, value, request) == nullptr) {
        return nullptr;
    }
    // UpdateOnly?: boolean
    if (GetNotificationIsUpdateOnly(env, value, request) == nullptr) {
        return nullptr;
    }
    // isRemoveAllowed?: boolean
    if (GetNotificationIsRemoveAllowed(env, value, request) == nullptr) {
        return nullptr;
    }
    // forceDistributed?: boolean
    if (GetNotificationForceDistributed(env, value, request) == nullptr) {
        return nullptr;
    }
    // notDistributed?: boolean
    if (GetNotificationIsNotDistributed(env, value, request) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationRequestByCustom(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    // content: NotificationContent
    if (GetNotificationContent(env, value, request) == nullptr) {
        return nullptr;
    }
    // slotType?: notification.SlotType
    if (GetNotificationSlotType(env, value, request) == nullptr) {
        return nullptr;
    }
    // wantAgent?: WantAgent
    if (GetNotificationWantAgent(env, value, request) == nullptr) {
        return nullptr;
    }
    // extraInfo?: {[key: string]: any}
    if (GetNotificationExtraInfo(env, value, request) == nullptr) {
        return nullptr;
    }
    // removalWantAgent?: WantAgent
    if (GetNotificationRemovalWantAgent(env, value, request) == nullptr) {
        return nullptr;
    }
    // maxScreenWantAgent?: WantAgent
    if (GetNotificationMaxScreenWantAgent(env, value, request) == nullptr) {
        return nullptr;
    }
    // actionButtons?: Array<NotificationActionButton>
    if (GetNotificationActionButtons(env, value, request) == nullptr) {
        return nullptr;
    }
    // smallIcon?: image.PixelMap
    if (GetNotificationSmallIcon(env, value, request) == nullptr) {
        return nullptr;
    }
    // largeIcon?: image.PixelMap
    if (GetNotificationLargeIcon(env, value, request) == nullptr) {
        return nullptr;
    }
    // overlayIcon?: image.PixelMap
    if (GetNotificationOverlayIcon(env, value, request) == nullptr) {
        return nullptr;
    }
    // distributedOption?:DistributedOptions
    if (GetNotificationRequestDistributedOptions(env, value, request) == nullptr) {
        return nullptr;
    }
    // template?: NotificationTemplate
    if (GetNotificationTemplate(env, value, request) == nullptr) {
        return nullptr;
    }
    // unifiedGroupInfo?: NotificationUnifiedGroupInfo
    if (GetNotificationUnifiedGroupInfo(env, value, request) == nullptr) {
        return nullptr;
    }
    // representativeBundle?: BundleOption
    if (GetNotificationBundleOption(env, value, request) == nullptr) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationRequest(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    if (!GetNotificationRequestByNumber(env, value, request)) {
        return nullptr;
    }
    if (!GetNotificationRequestByString(env, value, request)) {
        return nullptr;
    }
    if (!GetNotificationRequestByBool(env, value, request)) {
        return nullptr;
    }
    if (!GetNotificationRequestByCustom(env, value, request)) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationSmallIcon(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "smallIcon", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "smallIcon", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Argument type is not object.");
            std::string msg = "Incorrect parameter types. The type of smallIcon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, result);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        Common::PictureScale(pixelMap);
        request.SetLittleIcon(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLargeIcon(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "largeIcon", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "largeIcon", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of largeIcon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, result);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        Common::PictureScale(pixelMap);
        request.SetBigIcon(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationOverlayIcon(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "overlayIcon", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "overlayIcon", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of overlayIcon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, result);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        Common::PictureScale(pixelMap);
        request.SetOverlayIcon(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationSupportDisplayDevices(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool isArray = false;
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    napi_value supportDisplayDevices = nullptr;
    size_t strLen = 0;
    uint32_t length = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "supportDisplayDevices", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "supportDisplayDevices", &supportDisplayDevices);
        napi_is_array(env, supportDisplayDevices, &isArray);
        if (!isArray) {
            ANS_LOGE("Property supportDisplayDevices is expected to be an array.");
            return nullptr;
        }

        napi_get_array_length(env, supportDisplayDevices, &length);
        if (length == 0) {
            ANS_LOGE("The array is empty.");
            return nullptr;
        }
        std::vector<std::string> devices;
        for (size_t i = 0; i < length; i++) {
            napi_value line = nullptr;
            napi_get_element(env, supportDisplayDevices, i, &line);
            NAPI_CALL(env, napi_typeof(env, line, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            char str[STR_MAX_SIZE] = {0};
            NAPI_CALL(env, napi_get_value_string_utf8(env, line, str, STR_MAX_SIZE - 1, &strLen));
            devices.emplace_back(str);
            ANS_LOGI("supportDisplayDevices = %{public}s", str);
        }
        request.SetDevicesSupportDisplay(devices);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationSupportOperateDevices(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool isArray = false;
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    napi_value supportOperateDevices = nullptr;
    size_t strLen = 0;
    uint32_t length = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "supportOperateDevices", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "supportOperateDevices", &supportOperateDevices);
        napi_is_array(env, supportOperateDevices, &isArray);
        if (!isArray) {
            ANS_LOGE("Property supportOperateDevices is expected to be an array.");
            return nullptr;
        }

        napi_get_array_length(env, supportOperateDevices, &length);
        if (length == 0) {
            ANS_LOGE("The array is empty.");
            return nullptr;
        }
        std::vector<std::string> devices;
        for (size_t i = 0; i < length; i++) {
            napi_value line = nullptr;
            napi_get_element(env, supportOperateDevices, i, &line);
            NAPI_CALL(env, napi_typeof(env, line, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            char str[STR_MAX_SIZE] = {0};
            NAPI_CALL(env, napi_get_value_string_utf8(env, line, str, STR_MAX_SIZE - 1, &strLen));
            devices.emplace_back(str);
            ANS_LOGI("supportOperateDevices = %{public}s", str);
        }
        request.SetDevicesSupportOperate(devices);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationId(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int32_t notificationId = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "id", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "id", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of id must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &notificationId);
        request.SetNotificationId(notificationId);
    } else {
        ANS_LOGI("default notificationId = 0");
        request.SetNotificationId(0);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationSlotType(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasSlotType = false;
    bool hasNotificationSlotType = false;
    int32_t slotType = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "notificationSlotType", &hasNotificationSlotType));
    if (hasNotificationSlotType) {
        napi_get_named_property(env, value, "notificationSlotType", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &slotType);

        NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
        if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), outType)) {
            return nullptr;
        }
        request.SetSlotType(outType);
        ANS_LOGI("notificationSlotType = %{public}d", slotType);
        return NapiGetNull(env);
    }

    NAPI_CALL(env, napi_has_named_property(env, value, "slotType", &hasSlotType));
    if (hasSlotType) {
        napi_get_named_property(env, value, "slotType", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of slotType must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &slotType);

        NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
        if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), outType)) {
            return nullptr;
        }
        request.SetSlotType(outType);
        ANS_LOGI("slotType = %{public}d", slotType);
    } else {
        ANS_LOGI("default slotType = OTHER");
        request.SetSlotType(NotificationConstant::OTHER);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsOngoing(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isOngoing = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isOngoing", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isOngoing", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isOngoing must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isOngoing);
        request.SetInProgress(isOngoing);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsUnremovable(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isUnremovable = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isUnremovable", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isUnremovable", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isUnremovable must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isUnremovable);
        request.SetUnremovable(isUnremovable);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationDeliveryTime(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int64_t deliveryTime = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "deliveryTime", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "deliveryTime", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of deliveryTime must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int64(env, result, &deliveryTime);
        request.SetDeliveryTime(deliveryTime);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationtapDismissed(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool tapDismissed = true;

    NAPI_CALL(env, napi_has_named_property(env, value, "tapDismissed", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "tapDismissed", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of tapDismissed must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &tapDismissed);
        request.SetTapDismissed(tapDismissed);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationWantAgent(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool hasProperty = false;
    AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;

    NAPI_CALL(env, napi_has_named_property(env, value, "wantAgent", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "wantAgent", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of wantAgent must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_unwrap(env, result, (void **)&wantAgent);
        if (wantAgent == nullptr) {
            ANS_LOGE("Invalid object wantAgent");
            return nullptr;
        }
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> sWantAgent =
            std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgent);
        request.SetWantAgent(sWantAgent);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationExtraInfo(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "extraInfo", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "extraInfo", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of extraInfo must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        AAFwk::WantParams wantParams;
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            return nullptr;
        }

        std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>(wantParams);
        request.SetAdditionalData(extras);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGroupName(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "groupName", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "groupName", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of groupName must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        request.SetGroupName(str);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationRemovalWantAgent(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool hasProperty = false;
    AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;

    NAPI_CALL(env, napi_has_named_property(env, value, "removalWantAgent", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "removalWantAgent", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of removalWantAgent must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_unwrap(env, result, (void **)&wantAgent);
        if (wantAgent == nullptr) {
            ANS_LOGE("Invalid object removalWantAgent");
            return nullptr;
        }
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> removeWantAgent =
            std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgent);
        if ((uint32_t)removeWantAgent->GetPendingWant()->GetType(
            removeWantAgent->GetPendingWant()->GetTarget()) >= OPERATION_MAX_TYPE) {
            request.SetRemovalWantAgent(removeWantAgent);
        }
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationMaxScreenWantAgent(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool hasProperty = false;
    AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;

    NAPI_CALL(env, napi_has_named_property(env, value, "maxScreenWantAgent", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "maxScreenWantAgent", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of maxScreenWantAgent must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_unwrap(env, result, (void **)&wantAgent);
        if (wantAgent == nullptr) {
            ANS_LOGE("Invalid object maxScreenWantAgent");
            return nullptr;
        }
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> maxScreenWantAgent =
            std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgent);
        request.SetMaxScreenWantAgent(maxScreenWantAgent);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationAutoDeletedTime(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int64_t autoDeletedTime = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "autoDeletedTime", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "autoDeletedTime", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of deliveryTime must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int64(env, result, &autoDeletedTime);
        request.SetAutoDeletedTime(autoDeletedTime);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationClassification(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "classification", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "classification", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of classification must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        request.SetClassification(str);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationAppMessageId(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, "appMessageId", &hasProperty));
    if (!hasProperty) {
        return NapiGetNull(env);
    }

    auto appMessageIdValue = AppExecFwk::GetPropertyValueByPropertyName(env, value, "appMessageId", napi_string);
    if (appMessageIdValue == nullptr) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of appMessageId must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    std::string appMessageId = AppExecFwk::UnwrapStringFromJS(env, appMessageIdValue);
    request.SetAppMessageId(appMessageId);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationSound(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, "sound", &hasProperty));
    if (!hasProperty) {
        return NapiGetNull(env);
    }

    auto soundValue = AppExecFwk::GetPropertyValueByPropertyName(env, value, "sound", napi_string);
    if (soundValue == nullptr) {
        ANS_LOGE("Wrong argument type. String sound expected.");
        std::string msg = "Incorrect parameter types. The type of sound must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    std::string sound = AppExecFwk::UnwrapStringFromJS(env, soundValue);
    request.SetSound(sound);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationColor(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int32_t color = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "color", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "color", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of color must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &color);
        if (color < 0) {
            ANS_LOGE("Wrong argument type. Natural number expected.");
            return nullptr;
        }
        request.SetColor(color);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationColorEnabled(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool colorEnabled = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "colorEnabled", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "colorEnabled", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of colorEnabled must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &colorEnabled);
        request.SetColorEnabled(colorEnabled);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsAlertOnce(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isAlertOnce = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isAlertOnce", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isAlertOnce", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isAlertOnce must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isAlertOnce);
        request.SetAlertOneTime(isAlertOnce);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsStopwatch(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isStopwatch = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isStopwatch", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isStopwatch", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isStopwatch must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isStopwatch);
        request.SetShowStopwatch(isStopwatch);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsCountDown(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isCountDown = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isCountDown", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isCountDown", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isCountDown must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isCountDown);
        request.SetCountdownTimer(isCountDown);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationStatusBarText(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "statusBarText", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "statusBarText", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of statusBarText must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        request.SetStatusBarText(str);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLabel(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "label", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "label", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of label must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        request.SetLabel(str);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationBadgeIconStyle(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int32_t badgeIconStyle = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "badgeIconStyle", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "badgeIconStyle", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of badgeIconStyle must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &badgeIconStyle);
        request.SetBadgeIconStyle(static_cast<NotificationRequest::BadgeStyle>(badgeIconStyle));
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationShowDeliveryTime(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool showDeliveryTime = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "showDeliveryTime", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "showDeliveryTime", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of showDeliveryTime must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &showDeliveryTime);
        request.SetShowDeliveryTime(showDeliveryTime);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsUpdateOnly(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isUpdateOnly = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "updateOnly", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "updateOnly", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of updateOnly must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isUpdateOnly);
        request.SetUpdateOnly(isUpdateOnly);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsRemoveAllowed(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isRemoveAllowed = true;

    NAPI_CALL(env, napi_has_named_property(env, value, "isRemoveAllowed", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isRemoveAllowed", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isRemoveAllowed must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isRemoveAllowed);
        request.SetRemoveAllowed(isRemoveAllowed);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationForceDistributed(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool forceDistributed = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "forceDistributed", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "forceDistributed", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of forceDistributed must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &forceDistributed);
        request.SetForceDistributed(forceDistributed);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsNotDistributed(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool notDistributed = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "notDistributed", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "notDistributed", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of notDistributed must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &notDistributed);
        request.SetNotDistributed(notDistributed);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationActionButtons(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    bool isArray = false;
    napi_valuetype valuetype = napi_undefined;
    napi_value actionButtons = nullptr;
    uint32_t length = 0;
    bool hasProperty = false;

    napi_has_named_property(env, value, "actionButtons", &hasProperty);
    if (!hasProperty) {
        return Common::NapiGetNull(env);
    }

    request.SetIsCoverActionButtons(true);
    napi_get_named_property(env, value, "actionButtons", &actionButtons);
    napi_is_array(env, actionButtons, &isArray);
    if (!isArray) {
        ANS_LOGE("Property actionButtons is expected to be an array.");
        return nullptr;
    }
    napi_get_array_length(env, actionButtons, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return Common::NapiGetNull(env);
    }
    for (size_t i = 0; i < length; i++) {
        napi_value actionButton = nullptr;
        napi_get_element(env, actionButtons, i, &actionButton);
        NAPI_CALL(env, napi_typeof(env, actionButton, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of actionButtons must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        std::shared_ptr<NotificationActionButton> pActionButton = nullptr;
        if (GetNotificationActionButtonsDetailed(env, actionButton, pActionButton) == nullptr) {
            return nullptr;
        }
        request.AddActionButton(pActionButton);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationActionButtonsDetailed(
    const napi_env &env, const napi_value &actionButton, std::shared_ptr<NotificationActionButton> &pActionButton)
{
    ANS_LOGD("enter");

    if (!GetNotificationActionButtonsDetailedBasicInfo(env, actionButton, pActionButton)) {
        return nullptr;
    }
    if (!GetNotificationActionButtonsDetailedByExtras(env, actionButton, pActionButton)) {
        return nullptr;
    }
    if (!GetNotificationUserInput(env, actionButton, pActionButton)) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationActionButtonsDetailedBasicInfo(
    const napi_env &env, const napi_value &actionButton, std::shared_ptr<NotificationActionButton> &pActionButton)
{
    ANS_LOGD("enter");
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_value value = nullptr;
    std::string title;
    AbilityRuntime::WantAgent::WantAgent *wantAgentPtr = nullptr;
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent;

    // title: string
    NAPI_CALL(env, napi_has_named_property(env, actionButton, "title", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property title expected.");
        return nullptr;
    }
    napi_get_named_property(env, actionButton, "title", &value);
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, str, STR_MAX_SIZE - 1, &strLen));
    title = str;
    if (title.empty()) {
        ANS_LOGE("Property title in actionButton cannot be empty, but get an empty title in publish process.");
        std::string msg = "Incorrect parameter types.The content of property title in actionButton cannot be empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    // wantAgent: WantAgent
    NAPI_CALL(env, napi_has_named_property(env, actionButton, "wantAgent", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property wantAgent expected.");
        return nullptr;
    }
    napi_get_named_property(env, actionButton, "wantAgent", &value);
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of wantAgent must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_unwrap(env, value, (void **)&wantAgentPtr);
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Invalid object wantAgent");
        return nullptr;
    }
    wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgentPtr);

    // icon?: image.PixelMap
    NAPI_CALL(env, napi_has_named_property(env, actionButton, "icon", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, actionButton, "icon", &value);
        NAPI_CALL(env, napi_typeof(env, value, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of icon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, value);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
    }
    pActionButton = NotificationActionButton::Create(pixelMap, title, wantAgent);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationActionButtonsDetailedByExtras(
    const napi_env &env, const napi_value &actionButton, std::shared_ptr<NotificationActionButton> &pActionButton)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    if (!pActionButton) {
        ANS_LOGE("pActionButton is nullptr");
        return nullptr;
    }

    // extras?: {[key: string]: any}
    NAPI_CALL(env, napi_has_named_property(env, actionButton, "extras", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, actionButton, "extras", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of extras must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        AAFwk::WantParams wantParams;
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            return nullptr;
        }
        pActionButton->AddAdditionalData(wantParams);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationBadgeNumber(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    int32_t badgeNumber = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "badgeNumber", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "badgeNumber", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of badgeNumber must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        napi_get_value_int32(env, result, &badgeNumber);
        if (badgeNumber < 0) {
            ANS_LOGE("Wrong badge number.");
            return nullptr;
        }

        request.SetBadgeNumber(badgeNumber);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUnifiedGroupInfo(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, "unifiedGroupInfo", &hasProperty));
    if (!hasProperty) {
        return NapiGetNull(env);
    }

    auto info = AppExecFwk::GetPropertyValueByPropertyName(env, value, "unifiedGroupInfo", napi_object);
    if (info == nullptr) {
        ANS_LOGE("Wrong argument type. object expected.");
        std::string msg = "Incorrect parameter types. The type of unifiedGroupInfo must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    std::shared_ptr<NotificationUnifiedGroupInfo> unifiedGroupInfo = std::make_shared<NotificationUnifiedGroupInfo>();
    // key?: string
    auto jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, info, "key", napi_string);
    if (jsValue != nullptr) {
        std::string key = AppExecFwk::UnwrapStringFromJS(env, jsValue);
        unifiedGroupInfo->SetKey(key);
    }

    // title?: string
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, info, "title", napi_string);
    if (jsValue != nullptr) {
        std::string title = AppExecFwk::UnwrapStringFromJS(env, jsValue);
        unifiedGroupInfo->SetTitle(title);
    }

    // content?: string
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, info, "content", napi_string);
    if (jsValue != nullptr) {
        std::string content = AppExecFwk::UnwrapStringFromJS(env, jsValue);
        unifiedGroupInfo->SetContent(content);
    }

    // sceneName?: string
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, info, "sceneName", napi_string);
    if (jsValue != nullptr) {
        std::string sceneName = AppExecFwk::UnwrapStringFromJS(env, jsValue);
        unifiedGroupInfo->SetSceneName(sceneName);
    }

    // extraInfo?: {[key:string] : any}
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, info, "extraInfo", napi_object);
    if (jsValue != nullptr) {
        std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, jsValue, *extras)) {
            return nullptr;
        }
        unifiedGroupInfo->SetExtraInfo(extras);
    }

    request.SetUnifiedGroupInfo(unifiedGroupInfo);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationControlFlags(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("Called.");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    uint32_t notificationControlFlags = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "notificationControlFlags", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "notificationControlFlags", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of notificationControlFlags must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        napi_get_value_uint32(env, result, &notificationControlFlags);
        request.SetNotificationControlFlags(notificationControlFlags);
    }

    return NapiGetNull(env);
}

void Common::PictureScale(std::shared_ptr<Media::PixelMap> pixelMap)
{
    int32_t size = pixelMap->GetByteCount();
    if (size <= MAX_ICON_SIZE) {
        return;
    }
    int32_t width = pixelMap->GetWidth();
    int32_t height = pixelMap->GetHeight();
    float Axis = MAX_PIXEL_SIZE / std::max(width, height);
    pixelMap->scale(Axis, Axis, Media::AntiAliasingOption::HIGH);
}
}
}
