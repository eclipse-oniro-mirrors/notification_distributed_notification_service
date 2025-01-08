/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "notification_icon_button.h"
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_napi.h"

namespace OHOS {
using namespace Global::Resource;
namespace NotificationNapi {
napi_value Common::SetNotificationLocalLiveViewContent(
    const napi_env &env, NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }
    OHOS::Notification::NotificationLocalLiveViewContent *localLiveViewContent =
        static_cast<OHOS::Notification::NotificationLocalLiveViewContent *>(basicContent);
    if (localLiveViewContent == nullptr) {
        ANS_LOGE("localLiveViewContent is null");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationBasicContent(env, localLiveViewContent, result)) {
        ANS_LOGE("SetNotificationBasicContent call failed");
        return NapiGetBoolean(env, false);
    }

    // typeCode: int32_t
    napi_create_int32(env, localLiveViewContent->GetType(), &value);
    napi_set_named_property(env, result, "typeCode", value);

    // capsule: NotificationCapsule
    if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE)) {
        napi_value capsule = nullptr;
        napi_create_object(env, &capsule);
        if (!SetCapsule(env, localLiveViewContent->GetCapsule(), capsule)) {
            ANS_LOGE("SetCapsule call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "capsule", capsule);
    }

    // button: NotificationLocalLiveViewButton
    if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON)) {
        napi_value button = nullptr;
        napi_create_object(env, &button);
        if (!SetButton(env, localLiveViewContent->GetButton(), button)) {
            ANS_LOGE("SetButton call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "button", button);
    }

    // cardButtons?: Array<NotificationIconButton>;
    if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CARD_BUTTON)) {
        napi_value cardBtn = nullptr;
        napi_create_array_with_length(env, localLiveViewContent->GetCardButton().size(), &cardBtn);
        if (!SetCardButton(env, localLiveViewContent->GetCardButton(), cardBtn)) {
            ANS_LOGE("SetCardButton call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "cardButtons", cardBtn);
    }

    // liveViewType?: LiveViewTypes
    LiveViewTypes outType = LiveViewTypes::LIVE_VIEW_ACTIVITY;
    if (!AnsEnumUtil::LiveViewTypesCToJS(localLiveViewContent->GetLiveViewType(), outType)) {
        ANS_LOGE("Liveview type is invalid");
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "liveViewType", value);

    // progress: NotificationProgress
    if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS)) {
        napi_value progress = nullptr;
        napi_create_object(env, &progress);
        if (!SetProgress(env, localLiveViewContent->GetProgress(), progress)) {
            ANS_LOGE("SetProgress call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "progress", progress);
    }

    // time: NotificationTime
    if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::TIME)) {
        napi_value time = nullptr;
        napi_create_object(env, &time);
        bool flag = localLiveViewContent->isFlagExist(
            NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
        if (!SetTime(env, localLiveViewContent->GetTime(), time, flag)) {
            ANS_LOGE("SetMessageUser call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "time", time);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetCapsule(const napi_env &env, const NotificationCapsule &capsule, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;
    // title: string
    napi_create_string_utf8(env, capsule.GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "title", value);

    // backgroundColor: string
    napi_create_string_utf8(env, capsule.GetBackgroundColor().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "backgroundColor", value);

    // content: string
    napi_create_string_utf8(env, capsule.GetContent().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "content", value);

    // icon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> icon = capsule.GetIcon();
    if (icon) {
        napi_value iconResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        iconResult = Media::PixelMapNapi::CreatePixelMap(env, icon);
        NAPI_CALL(env, napi_typeof(env, iconResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGW("iconResult is undefined");
            napi_set_named_property(env, result, "icon", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "icon", iconResult);
        }
    }

    // time?: number
    napi_create_int32(env, capsule.GetTime(), &value);
    napi_set_named_property(env, result, "time", value);

    // capsuleButtons?: Array<NotificationIconButton>;
    napi_value cardBtn = nullptr;
    napi_create_array_with_length(env, capsule.GetCapsuleButton().size(), &cardBtn);
    if (!SetCardButton(env, capsule.GetCapsuleButton(), cardBtn)) {
        ANS_LOGE("capsuleButton call failed");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "capsuleButtons", cardBtn);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetProgress(const napi_env &env, const NotificationProgress &progress, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;
    // currentValue: int32_t
    napi_create_int32(env, progress.GetCurrentValue(), &value);
    napi_set_named_property(env, result, "currentValue", value);

    // maxValue: int32_t
    napi_create_int32(env, progress.GetMaxValue(), &value);
    napi_set_named_property(env, result, "maxValue", value);

    // isPercentage: bool
    napi_get_boolean(env, progress.GetIsPercentage(), &value);
    napi_set_named_property(env, result, "isPercentage", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetTime(const napi_env &env, const NotificationTime &time,
    napi_value &result, bool isInitialTimeExist)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;
    // initialTime: int32_t
    if (isInitialTimeExist) {
        napi_create_int32(env, time.GetInitialTime(), &value);
        napi_set_named_property(env, result, "initialTime", value);
    }

    // isCountDown: bool
    napi_get_boolean(env, time.GetIsCountDown(), &value);
    napi_set_named_property(env, result, "isCountDown", value);

    // isPaused: bool
    napi_get_boolean(env, time.GetIsPaused(), &value);
    napi_set_named_property(env, result, "isPaused", value);

    // isInTitle: bool
    napi_get_boolean(env, time.GetIsInTitle(), &value);
    napi_set_named_property(env, result, "isInTitle", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetObjectStringProperty(const napi_env& env, napi_value& object,
    const std::string& key, const std::string& value)
{
    napi_value property;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &property);
    if (status != napi_ok) {
        ANS_LOGE("Failed to create value.");
        return nullptr;
    }
    status = napi_set_named_property(env, object, key.c_str(), property);
    if (status != napi_ok) {
        ANS_LOGE("Failed to set locale property");
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::SetObjectUint32Property(const napi_env &env, napi_value& object,
    const std::string& key, uint32_t value)
{
    napi_value property;
    napi_status status = napi_create_uint32(env, value, &property);
    if (status != napi_ok) {
        ANS_LOGE("Failed to create value.");
        return nullptr;
    }

    status = napi_set_named_property(env, object, key.c_str(), property);
    if (status != napi_ok) {
        ANS_LOGE("Failed to set locale property");
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::SetResourceObject(napi_env env, const std::shared_ptr<ResourceManager::Resource> &resource,
    napi_value &object)
{
    if (SetObjectStringProperty(env, object, "bundleName", resource->bundleName) == nullptr) {
        ANS_LOGE("Failed to set property bundleName");
        return NapiGetBoolean(env, false);
    }
    if (SetObjectStringProperty(env, object, "moduleName", resource->moduleName) == nullptr) {
        ANS_LOGE("Failed to set property moduleName");
        return NapiGetBoolean(env, false);
    }
    if (SetObjectUint32Property(env, object, "id", resource->id) == nullptr) {
        ANS_LOGE("Failed to set property id");
        return NapiGetBoolean(env, false);
    }
    return NapiGetBoolean(env, true);
}

napi_value Common::SetButton(const napi_env &env, const NotificationLocalLiveViewButton &button, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;

    // buttonNames: Array<String>
    napi_value arr = nullptr;
    int count = 0;
    napi_create_array(env, &arr);
    for (auto vec : button.GetAllButtonNames()) {
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, arr, count, value);
        count++;
    }
    napi_set_named_property(env, result, "names", arr);

    // buttonIcons: Array<PixelMap>
    napi_value iconArr = nullptr;
    int iconCount = 0;
    napi_create_array(env, &iconArr);

    std::vector<std::shared_ptr<Media::PixelMap>> icons = button.GetAllButtonIcons();
    for (auto vec : icons) {
        if (!vec) {
            continue;
        }
        // buttonIcon
        napi_value iconResult = nullptr;
        iconResult = Media::PixelMapNapi::CreatePixelMap(env, vec);
        napi_set_element(env, iconArr, iconCount, iconResult);
        iconCount++;
    }
    napi_set_named_property(env, result, "icons", iconArr);

    // buttonIcons: Array<Resource>
    iconCount = 0;
    napi_value resourceArr = nullptr;
    napi_create_array(env, &resourceArr);
    auto iconResources = button.GetAllButtonIconResource();
    for (auto resource : iconResources) {
        napi_value object;
        napi_status status = napi_create_object(env, &object);
        if (status != napi_ok) {
            ANS_LOGE("Failed to create Configuration object");
            return NapiGetBoolean(env, false);
        }
        if (!SetResourceObject(env, resource, object)) {
            return NapiGetBoolean(env, false);
        }
        napi_set_element(env, resourceArr, iconCount, object);
        iconCount++;
    }
    napi_set_named_property(env, result, "iconsResource", resourceArr);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetCardButton(const napi_env &env, const std::vector<NotificationIconButton> buttons,
    napi_value &result)
{
    ANS_LOGD("enter");

    int iconCount = 0;
    napi_value value = nullptr;
    for (auto btn : buttons) {
        // name: string
        napi_value item = nullptr;
        napi_status status = napi_create_object(env, &item);
        if (status != napi_ok) {
            ANS_LOGE("Failed to create card button item");
            return NapiGetBoolean(env, false);
        }
        napi_create_string_utf8(env, btn.GetName().c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_named_property(env, item, "name", value);

        // text?: string;
        napi_create_string_utf8(env, btn.GetText().c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_named_property(env, item, "text", value);

        // hidePanel?: boolean;
        napi_get_boolean(env, btn.GetHidePanel(), &value);
        napi_set_named_property(env, item, "hidePanel", value);

        // iconResource: Resource;
        napi_value object;
        status = napi_create_object(env, &object);
        if (status != napi_ok) {
            ANS_LOGE("Failed to create card button item.resource");
            return NapiGetBoolean(env, false);
        }
        // resource | pixelMap
        std::shared_ptr<Media::PixelMap> icon = btn.GetIconImage();
        if (icon) {
            object = Media::PixelMapNapi::CreatePixelMap(env, icon);
        } else {
            if (!SetResourceObject(env, btn.GetIconResource(), object)) {
                return NapiGetBoolean(env, false);
            }
        }

        napi_set_named_property(env, item, "iconResource", object);
        status = napi_set_element(env, result, iconCount, item);
        iconCount++;
    }
    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationLiveViewContent(
    const napi_env &env, NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("BasicContent is null");
        return NapiGetBoolean(env, false);
    }

    // lockScreenPicture?: pixelMap
    if (!SetLockScreenPicture(env, basicContent, result)) {
        ANS_LOGE("lockScreenPicture is null");
        return NapiGetBoolean(env, false);
    }

    auto liveViewContent = static_cast<NotificationLiveViewContent *>(basicContent);
    if (liveViewContent == nullptr) {
        ANS_LOGE("LiveViewContent is null");
        return NapiGetBoolean(env, false);
    }

    // status: LiveViewStatus
    LiveViewStatus outType = LiveViewStatus::LIVE_VIEW_BUTT;
    if (!AnsEnumUtil::LiveViewStatusCToJS(liveViewContent->GetLiveViewStatus(), outType)) {
        ANS_LOGE("Liveview status is invalid");
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "status", value);

    // version?: uint32_t
    napi_create_int32(env, static_cast<int32_t>(liveViewContent->GetVersion()), &value);
    napi_set_named_property(env, result, "version", value);

    // extraInfo?: {[key:string] : any}
    std::shared_ptr<AAFwk::WantParams> extraInfoData = liveViewContent->GetExtraInfo();
    if (extraInfoData != nullptr) {
        napi_value extraInfo = OHOS::AppExecFwk::WrapWantParams(env, *extraInfoData);
        napi_set_named_property(env, result, "extraInfo", extraInfo);
    }

    // pictureInfo?: {[key, string]: Array<image.pixelMap>}
    if (liveViewContent->GetPicture().empty()) {
        ANS_LOGD("No pictures in live view.");
        return NapiGetBoolean(env, true);
    }

    napi_value pictureMapObj = SetLiveViewPictureInfo(env, liveViewContent->GetPicture());
    if (pictureMapObj == nullptr) {
        ANS_LOGE("Set live view picture map failed.");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "pictureInfo", pictureMapObj);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetLiveViewPictureInfo(
    const napi_env &env, const std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ANS_LOGD("enter");

    napi_value pictureMapObj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &pictureMapObj));

    for (auto iter = pictureMap.begin(); iter != pictureMap.end(); iter++) {
        int count = 0;
        napi_value picturesObj = nullptr;
        napi_create_array(env, &picturesObj);
        for (auto picture : iter->second) {
            napi_value pictureObj = Media::PixelMapNapi::CreatePixelMap(env, picture);
            napi_set_element(env, picturesObj, count, pictureObj);
            count++;
        }

        if (count > 0) {
            napi_set_named_property(env, pictureMapObj, iter->first.c_str(), picturesObj);
        }
    }

    return pictureMapObj;
}

napi_value Common::GetNotificationLocalLiveViewContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, result, "systemLiveView", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property localLiveView expected.");
        return nullptr;
    }
    napi_get_named_property(env, result, "systemLiveView", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> localLiveViewContent =
        std::make_shared<OHOS::Notification::NotificationLocalLiveViewContent>();
    if (localLiveViewContent == nullptr) {
        ANS_LOGE("localLiveViewContent is null");
        return nullptr;
    }

    if (GetNotificationLocalLiveViewContentDetailed(env, contentResult, localLiveViewContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(localLiveViewContent));

    // set isOnGoing of live view true
    request.SetInProgress(true);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewCapsule(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    napi_value capsuleResult = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    napi_value result = nullptr;
    int32_t intValue;

    ANS_LOGD("enter");

    NAPI_CALL(env, napi_has_named_property(env, contentResult, "capsule", &hasProperty));

    napi_get_named_property(env, contentResult, "capsule", &capsuleResult);
    NAPI_CALL(env, napi_typeof(env, capsuleResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    NotificationCapsule capsule;

    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "title", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "title", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of title must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        capsule.SetTitle(str);
        ANS_LOGD("capsule title = %{public}s", str);
    }

    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "backgroundColor", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "backgroundColor", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of backgroundColor must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        capsule.SetBackgroundColor(str);
        ANS_LOGD("capsule backgroundColor = %{public}s", str);
    }

    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "content", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "content", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of content must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        capsule.SetContent(str);
        ANS_LOGD("capsule content = %{public}s", str);
    }

    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "icon", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "icon", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of icon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, result);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        capsule.SetIcon(pixelMap);
        ANS_LOGD("capsule icon = %{public}d", pixelMap->GetWidth());
    }

    //time?: number
    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "time", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "time", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        napi_get_value_int32(env, result, &intValue);
        capsule.SetTime(intValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, capsuleResult, "capsuleButtons", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, capsuleResult, "capsuleButtons", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        if (hasProperty && GetNotificationLocalLiveViewCapsuleCardButton(env, result, capsule) == nullptr) {
            return nullptr;
        }
    }

    content->SetCapsule(capsule);
    content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewCardButton(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    napi_value buttonResult = nullptr;

    ANS_LOGD("enter");
    napi_get_named_property(env, contentResult, "cardButtons", &buttonResult);
    
    // 解析iconbutton数组
    std::vector<NotificationIconButton> cardButtons;
    if (GetNotificationIconButton(env, buttonResult, cardButtons) == nullptr) {
        return nullptr;
    }

    content->SetCardButton(cardButtons);
    content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CARD_BUTTON);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewCapsuleCardButton(
    const napi_env &env, const napi_value &capsuletResult,
    OHOS::Notification::NotificationCapsule &capsule)
{
    ANS_LOGD("enter");
    std::vector<NotificationIconButton> cardButtons;
    if (GetNotificationIconButton(env, capsuletResult, cardButtons) == nullptr) {
        return nullptr;
    }

    capsule.SetCapsuleButton(cardButtons);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationIconButton(
    const napi_env &env, const napi_value &buttonResult, std::vector<NotificationIconButton> &cardButtons)
{
    // cardButton_item?: NotificationIconButton;
    napi_value cardButton = nullptr;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;

    bool isArray = false;
    bool boolValue = false;
    uint32_t length = 0;

    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};
    bool hasProperty = false;

    ANS_LOGD("enter");
    napi_is_array(env, buttonResult, &isArray);
    if (!isArray) {
        ANS_LOGE("Property names is expected to be an array.");
        return nullptr;
    }
    napi_get_array_length(env, buttonResult, &length);
    if (length > BUTTON_MAX_SIZE) {
        length = BUTTON_MAX_SIZE;
    }

    for (size_t i = 0; i < length; i++) {
        napi_get_element(env, buttonResult, i, &cardButton);

        NAPI_CALL(env, napi_typeof(env, cardButton, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        // 数组item
        NotificationIconButton button;
        // name: string
        NAPI_CALL(env, napi_has_named_property(env, cardButton, "name", &hasProperty));
        if (!hasProperty) {
            ANS_LOGE("Property name expected.");
            return nullptr;
        } else {
            napi_get_named_property(env, cardButton, "name", &result);
            NAPI_CALL(env, napi_typeof(env, result, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
            button.SetName(str);
        }

        // iconResource: Resource
        NAPI_CALL(env, napi_has_named_property(env, cardButton, "iconResource", &hasProperty));
        if (!hasProperty) {
            ANS_LOGE("Property iconResource expected.");
            return nullptr;
        } else {
            // if icon type is Rersouce, get the resource object and return.
            napi_value iconResource = nullptr;
            napi_get_named_property(env, cardButton, "iconResource", &iconResource);
            NAPI_CALL(env, napi_typeof(env, iconResource, &valuetype));
            if (valuetype != napi_object) {
                ANS_LOGE("Wrong argument type. iconResource Object expected.");
                return nullptr;
            }

            // icon?: Resource
            auto resource = std::make_shared<ResourceManager::Resource>();
            if (Common::GetResourceObject(env, resource, iconResource) == nullptr) {
                ANS_LOGI("Invalid icon resource object or not resource.");
            } else {
                button.SetIconResource(resource);
            }

            // icon?: image.PixelMap
            auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, iconResource);
            if (pixelMap == nullptr) {
                ANS_LOGE("Invalid pixelMap object is null.");
            } else {
                button.SetIconImage(pixelMap);
            }
        }

        // text?: string
        NAPI_CALL(env, napi_has_named_property(env, cardButton, "text", &hasProperty));
        if (hasProperty) {
            napi_get_named_property(env, cardButton, "text", &result);
            NAPI_CALL(env, napi_typeof(env, result, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
            button.SetText(str);
        }

        // hidePanel?: boolean;
        NAPI_CALL(env, napi_has_named_property(env, cardButton, "hidePanel", &hasProperty));
        if (hasProperty) {
            napi_get_named_property(env, cardButton, "hidePanel", &result);
            NAPI_CALL(env, napi_typeof(env, result, &valuetype));
            if (valuetype != napi_boolean) {
                ANS_LOGE("Wrong argument type. bool expected.");
                return nullptr;
            }
            napi_get_value_bool(env, result, &boolValue);
            button.SetHidePanel(boolValue);
        }

        cardButtons.push_back(button);
        ANS_LOGD("icon button = %{public}s", button.Dump().c_str());
    }

    return NapiGetNull(env);
}

napi_value Common::GetResourceObject(napi_env env,
    std::shared_ptr<ResourceManager::Resource> &resource, napi_value &value)
{
    napi_value name;
    size_t strLen = 0;
    char str[STR_MAX_SIZE] = {0};
    std::vector<std::string> typeName = {"bundleName", "moduleName"};
    for (const std::string& type: typeName) {
        napi_status status = napi_get_named_property(env, value, type.c_str(), &name);
        if (status != napi_ok || name == nullptr) {
            ANS_LOGE("Failed to get resource name property");
            return nullptr;
        }
        napi_valuetype valueType = napi_valuetype::napi_undefined;
        NAPI_CALL(env, napi_typeof(env, name, &valueType));
        if (valueType != napi_string) {
            ANS_LOGE("Failed to get resource type %{public}d", valueType);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, name, str, STR_MAX_SIZE - 1, &strLen));
        if (type == "bundleName") {
            resource->bundleName = str;
        } else if (type == "moduleName") {
            resource->moduleName = str;
        }
    }

    napi_value id;
    napi_status status = napi_get_named_property(env, value, "id", &id);
    if (status != napi_ok || id == nullptr) {
        ANS_LOGE("Failed to get resource id property");
        return nullptr;
    }
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    napi_typeof(env, id, &valueType);
    if (valueType != napi_number) {
        ANS_LOGE("Failed to get resource name string");
        std::string msg = "Incorrect parameter types. The type of id must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int32_t resId = 0;
    status = napi_get_value_int32(env, id, &resId);
    if (status != napi_ok) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }
    resource->id = resId;
    ANS_LOGE("Get to get resource bundleName %{public}s moduleName %{public}s id %{public}d",
        resource->bundleName.c_str(), resource->moduleName.c_str(), resource->id);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewButton(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool isArray = false;
    uint32_t length = 0;
    napi_value buttonResult = nullptr;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;

    ANS_LOGD("enter");

    napi_get_named_property(env, contentResult, "button", &buttonResult);
    NAPI_CALL(env, napi_typeof(env, buttonResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    NotificationLocalLiveViewButton button;

    NAPI_CALL(env, napi_has_named_property(env, buttonResult, "names", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, buttonResult, "names", &result);
        napi_is_array(env, result, &isArray);
        if (!isArray) {
            ANS_LOGE("Property names is expected to be an array.");
            return nullptr;
        }
        napi_get_array_length(env, result, &length);
        for (size_t i = 0; i < length; i++) {
            napi_value buttonName = nullptr;
            napi_get_element(env, result, i, &buttonName);
            NAPI_CALL(env, napi_typeof(env, buttonName, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            NAPI_CALL(env, napi_get_value_string_utf8(env, buttonName, str, STR_MAX_SIZE - 1, &strLen));
            button.addSingleButtonName(str);
            ANS_LOGD("button buttonName = %{public}s.", str);
        }
    }

    NAPI_CALL(env, napi_has_named_property(env, buttonResult, "icons", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, buttonResult, "icons", &result);
        napi_is_array(env, result, &isArray);
        if (!isArray) {
            ANS_LOGE("Property icons is expected to be an array.");
            return nullptr;
        }
        napi_get_array_length(env, result, &length);
        for (size_t i = 0; i < length; i++) {
            napi_value buttonIcon = nullptr;
            std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
            napi_get_element(env, result, i, &buttonIcon);
            NAPI_CALL(env, napi_typeof(env, buttonIcon, &valuetype));
            if (valuetype != napi_object) {
                ANS_LOGE("Wrong argument type. Object expected.");
                return nullptr;
            }
            pixelMap = Media::PixelMapNapi::GetPixelMap(env, buttonIcon);
            if (pixelMap != nullptr && static_cast<uint32_t>(pixelMap->GetByteCount()) <= MAX_ICON_SIZE) {
                button.addSingleButtonIcon(pixelMap);
            } else {
                ANS_LOGE("Invalid pixelMap object or pixelMap is over size.");
                return nullptr;
            }
        }
    }

    NAPI_CALL(env, napi_has_named_property(env, buttonResult, "iconsResource", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, buttonResult, "iconsResource", &result);
        napi_is_array(env, result, &isArray);
        if (!isArray) {
            ANS_LOGE("Property icon resource is expected to be an array.");
            return nullptr;
        }
        napi_get_array_length(env, result, &length);
        for (size_t i = 0; i < length; i++) {
            napi_value iconResource = nullptr;
            auto resource = std::make_shared<ResourceManager::Resource>();
            napi_get_element(env, result, i, &iconResource);
            NAPI_CALL(env, napi_typeof(env, iconResource, &valuetype));
            if (valuetype != napi_object) {
                ANS_LOGE("Wrong argument type. Object expected.");
                return nullptr;
            }
            if (Common::GetResourceObject(env, resource, iconResource) == nullptr) {
                ANS_LOGW("Invalid icon resource object.");
                return nullptr;
            } else {
                button.addSingleButtonIconResource(resource);
            }
        }
    }

    ANS_LOGD("button buttonIcon = %{public}s", str);
    content->SetButton(button);
    content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewProgress(const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    int32_t intValue = -1;
    bool boolValue = false;
    napi_value progressResult = nullptr;

    ANS_LOGD("enter");

    napi_get_named_property(env, contentResult, "progress", &progressResult);
    NAPI_CALL(env, napi_typeof(env, progressResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    NotificationProgress progress;

    NAPI_CALL(env, napi_has_named_property(env, progressResult, "maxValue", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, progressResult, "maxValue", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            std::string msg = "Incorrect parameter types. The type of maxValue must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        napi_get_value_int32(env, result, &intValue);
        progress.SetMaxValue(intValue);
        ANS_LOGD("progress intValue = %{public}d", intValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, progressResult, "currentValue", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, progressResult, "currentValue", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of currentValue must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &intValue);
        progress.SetCurrentValue(intValue);
        ANS_LOGD("progress currentValue = %{public}d", intValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, progressResult, "isPercentage", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, progressResult, "isPercentage", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. bool expected.");
            std::string msg = "Incorrect parameter types. The type of isPercentage must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &boolValue);
        progress.SetIsPercentage(boolValue);
        ANS_LOGD("progress isPercentage = %{public}d", boolValue);
    }

    content->SetProgress(progress);
    content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewTime(const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    int32_t intValue = -1;
    bool boolValue = false;
    napi_value timeResult = nullptr;

    ANS_LOGD("enter");

    napi_get_named_property(env, contentResult, "time", &timeResult);
    NAPI_CALL(env, napi_typeof(env, timeResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    NotificationTime time;

    NAPI_CALL(env, napi_has_named_property(env, timeResult, "initialTime", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, timeResult, "initialTime", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of initialTime must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &intValue);
        time.SetInitialTime(intValue);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
        ANS_LOGD("time initialTime = %{public}d", intValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, timeResult, "isCountDown", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, timeResult, "isCountDown", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. bool expected.");
            std::string msg = "Incorrect parameter types. The type of isCountDown must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &boolValue);
        time.SetIsCountDown(boolValue);
        ANS_LOGD("time isCountDown = %{public}d", boolValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, timeResult, "isPaused", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, timeResult, "isPaused", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. bool expected.");
            std::string msg = "Incorrect parameter types. The type of isPaused must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &boolValue);
        time.SetIsPaused(boolValue);
        ANS_LOGD("time isPaused = %{public}d", boolValue);
    }

    NAPI_CALL(env, napi_has_named_property(env, timeResult, "isInTitle", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, timeResult, "isInTitle", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. bool expected.");
            std::string msg = "Incorrect parameter types. The type of isInTitle must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &boolValue);
        time.SetIsInTitle(boolValue);
        ANS_LOGD("time isInTitle = %{public}d", boolValue);
    }

    content->SetTime(time);
    content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLocalLiveViewContentDetailed(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> content)
{
    bool hasProperty = false;
    int32_t type = -1;
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;

    ANS_LOGD("enter");

    //title, text
    if (GetNotificationBasicContentDetailed(env, contentResult, content) == nullptr) {
        ANS_LOGE("Basic content get fail.");
        return nullptr;
    }

    // typeCode
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "typeCode", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property typeCode expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "typeCode", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument typeCode. Number expected.");
        std::string msg = "Incorrect parameter types. The type of typeCode must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &type);
    content->SetType(type);
    ANS_LOGD("localLiveView type = %{public}d", type);

    //capsule?
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "capsule", &hasProperty));
    if (hasProperty && GetNotificationLocalLiveViewCapsule(env, contentResult, content) == nullptr) {
        return nullptr;
    }

    //button?
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "button", &hasProperty));
    if (hasProperty && GetNotificationLocalLiveViewButton(env, contentResult, content) == nullptr) {
        return nullptr;
    }

    //cardButton?
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "cardButtons", &hasProperty));
    if (hasProperty && GetNotificationLocalLiveViewCardButton(env, contentResult, content) == nullptr) {
        return nullptr;
    }

    // liveViewType?: LiveViewTypes
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "liveViewType", &hasProperty));
    NotificationLocalLiveViewContent::LiveViewTypes outType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY;
    if (hasProperty && AppExecFwk::UnwrapInt32ByPropertyName(env, contentResult, "liveViewType", type)) {
        if (!AnsEnumUtil::LiveViewTypesJSToC(LiveViewTypes(type), outType)) {
            ANS_LOGE("The liveview types is not valid.");
            return nullptr;
        }
    }
    content->SetLiveViewType(outType);

    //progress?
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "progress", &hasProperty));
    if (hasProperty && GetNotificationLocalLiveViewProgress(env, contentResult, content) == nullptr) {
        return nullptr;
    }

    //time?
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "time", &hasProperty));
    if (hasProperty && GetNotificationLocalLiveViewTime(env, contentResult, content) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLiveViewContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_value contentResult = AppExecFwk::GetPropertyValueByPropertyName(env, result, "liveView", napi_object);
    if (contentResult == nullptr) {
        ANS_LOGE("Property liveView expected.");
        return nullptr;
    }

    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    if (liveViewContent == nullptr) {
        ANS_LOGE("LiveViewContent is null");
        return nullptr;
    }

    if (GetNotificationLiveViewContentDetailed(env, contentResult, liveViewContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(liveViewContent));

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLiveViewContentDetailed(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    ANS_LOGD("enter");

    // lockScreenPicture?: pixelMap
    if (GetLockScreenPicture(env, contentResult, liveViewContent) == nullptr) {
        ANS_LOGE("Failed to get lockScreenPicture from liveView content.");
        return nullptr;
    }

    // status: NotificationLiveViewContent::LiveViewStatus
    int32_t status = 0;
    if (!AppExecFwk::UnwrapInt32ByPropertyName(env, contentResult, "status", status)) {
        ANS_LOGE("Failed to get status from liveView content.");
        return nullptr;
    }
    NotificationLiveViewContent::LiveViewStatus outType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT;
    if (!AnsEnumUtil::LiveViewStatusJSToC(LiveViewStatus(status), outType)) {
        ANS_LOGE("The liveview status is not valid.");
        return nullptr;
    }
    liveViewContent->SetLiveViewStatus(outType);

    // version?: uint32_t
    napi_value jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult,
        "version", napi_number);
    if (jsValue != nullptr) {
        int32_t version = NotificationLiveViewContent::MAX_VERSION;
        NAPI_CALL(env, napi_get_value_int32(env, jsValue, &version));
        liveViewContent->SetVersion(version);
    }

    // extraInfo?: {[key:string] : any}
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "extraInfo", napi_object);
    if (jsValue != nullptr) {
        std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, jsValue, *extras)) {
            return nullptr;
        }
        liveViewContent->SetExtraInfo(extras);
    }

    //isOnlyLocalUpdate_?: boolean
    bool isLocalUpdateOnly = false;
    if (AppExecFwk::UnwrapBooleanByPropertyName(env, contentResult, "isLocalUpdateOnly", isLocalUpdateOnly)) {
        liveViewContent->SetIsOnlyLocalUpdate(isLocalUpdateOnly);
    }

    // pictureInfo?: {[key, string]: Array<image.pixelMap>}
    jsValue = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "pictureInfo", napi_object);
    if (jsValue == nullptr) {
        ANS_LOGI("No picture maps.");
        return NapiGetNull(env);
    }

    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap;
    if (GetLiveViewPictureInfo(env, jsValue, pictureMap) == nullptr) {
        ANS_LOGE("Failed to get picture map from liveView content.");
        return nullptr;
    }
    liveViewContent->SetPicture(pictureMap);

    return NapiGetNull(env);
}

napi_value Common::GetLiveViewPictures(
    const napi_env &env, const napi_value &picturesObj,
    std::vector<std::shared_ptr<Media::PixelMap>> &pictures)
{
    ANS_LOGD("enter");

    bool isArray = false;
    napi_is_array(env, picturesObj, &isArray);
    if (!isArray) {
        ANS_LOGE("The picture is not array.");
        return nullptr;
    }

    uint32_t length = 0;
    napi_get_array_length(env, picturesObj, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return nullptr;
    }

    for (uint32_t i = 0; i < length; ++i) {
        napi_value pictureObj = nullptr;
        napi_get_element(env, picturesObj, i, &pictureObj);
        if (!AppExecFwk::IsTypeForNapiValue(env, pictureObj, napi_object)) {
            ANS_LOGE("Wrong argument type. object expected.");
            break;
        }

        std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMapNapi::GetPixelMap(env, pictureObj);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid pixelMap.");
            break;
        }

        pictures.emplace_back(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::GetLiveViewPictureInfo(
    const napi_env &env, const napi_value &pictureMapObj,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> &pictureMap)
{
    ANS_LOGD("enter");

    napi_value pictureNamesObj = nullptr;
    uint32_t length = 0;
    if (napi_get_property_names(env, pictureMapObj, &pictureNamesObj) != napi_ok) {
        ANS_LOGE("Get picture names failed.");
        return nullptr;
    }
    napi_get_array_length(env, pictureNamesObj, &length);
    if (length == 0) {
        ANS_LOGE("The pictures name is empty.");
        return nullptr;
    }

    napi_value pictureNameObj = nullptr;
    napi_value picturesObj = nullptr;
    for (uint32_t index = 0; index < length; index++) {
        napi_get_element(env, pictureNamesObj, index, &pictureNameObj);
        std::string pictureName = AppExecFwk::UnwrapStringFromJS(env, pictureNameObj);
        ANS_LOGD("%{public}s called, get pictures of %{public}s.", __func__, pictureName.c_str());
        napi_get_named_property(env, pictureMapObj, pictureName.c_str(), &picturesObj);

        std::vector<std::shared_ptr<Media::PixelMap>> pictures;
        if (!GetLiveViewPictures(env, picturesObj, pictures)) {
            ANS_LOGE("Get pictures of %{public}s failed.", pictureName.c_str());
            break;
        }

        pictureMap[pictureName] = pictures;
    }

    return NapiGetNull(env);
}
}
}
