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
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
const char *Common::GetPropertyNameByContentType(ContentType type)
{
    switch (type) {
        case ContentType::NOTIFICATION_CONTENT_BASIC_TEXT: // normal?: NotificationBasicContent
            return "normal";
        case ContentType::NOTIFICATION_CONTENT_LONG_TEXT: // longText?: NotificationLongTextContent
            return "longText";
        case ContentType::NOTIFICATION_CONTENT_PICTURE: // picture?: NotificationPictureContent
            return "picture";
        case ContentType::NOTIFICATION_CONTENT_CONVERSATION: // conversation?: NotificationConversationalContent
            return "conversation";
        case ContentType::NOTIFICATION_CONTENT_MULTILINE: // multiLine?: NotificationMultiLineContent
            return "multiLine";
        case ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW: // systemLiveView?: NotificationLocalLiveViewContent
            return "systemLiveView";
        case ContentType::NOTIFICATION_CONTENT_LIVE_VIEW: // liveView?: NotificationLiveViewContent
            return "liveView";
        default:
            ANS_LOGE("ContentType is does not exist");
            return "null";
    }
}

napi_value Common::SetNotificationContentDetailed(const napi_env &env, const ContentType &type,
    const std::shared_ptr<NotificationContent> &content, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value ret = NapiGetBoolean(env, false);
    if (!content) {
        ANS_LOGE("content is null");
        return ret;
    }

    std::shared_ptr<NotificationBasicContent> basicContent = content->GetNotificationContent();
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return ret;
    }

    napi_value contentResult = nullptr;
    napi_create_object(env, &contentResult);
    switch (type) {
        case ContentType::NOTIFICATION_CONTENT_BASIC_TEXT: // normal?: NotificationBasicContent
            ret = SetNotificationBasicContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_LONG_TEXT: // longText?: NotificationLongTextContent
            ret = SetNotificationLongTextContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_PICTURE: // picture?: NotificationPictureContent
            ret = SetNotificationPictureContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_CONVERSATION: // conversation?: NotificationConversationalContent
            ret = SetNotificationConversationalContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_MULTILINE: // multiLine?: NotificationMultiLineContent
            ret = SetNotificationMultiLineContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW: // systemLiveView?: NotificationLocalLiveViewContent
            ret = SetNotificationLocalLiveViewContent(env, basicContent.get(), contentResult);
            break;
        case ContentType::NOTIFICATION_CONTENT_LIVE_VIEW: // liveView?: NotificationLiveViewContent
            ret = SetNotificationLiveViewContent(env, basicContent.get(), contentResult);
            break;
        default:
            ANS_LOGE("ContentType is does not exist");
            return nullptr;
    }
    if (ret) {
        const char *propertyName = GetPropertyNameByContentType(type);
        napi_set_named_property(env, result, propertyName, contentResult);
    }

    return ret;
}

napi_value Common::SetNotificationContent(
    const napi_env &env, const std::shared_ptr<NotificationContent> &content, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (content == nullptr) {
        ANS_LOGE("content is null");
        return NapiGetBoolean(env, false);
    }

    // contentType: ContentType
    NotificationContent::Type type = content->GetContentType();
    ContentType outType = ContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    if (!AnsEnumUtil::ContentTypeCToJS(type, outType)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "contentType", value);
    napi_set_named_property(env, result, "notificationContentType", value);

    if (!SetNotificationContentDetailed(env, outType, content, result)) {
        return NapiGetBoolean(env, false);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationBasicContent(
    const napi_env &env, const NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }

    // title: string
    napi_create_string_utf8(env, basicContent->GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "title", value);

    // text: string
    napi_create_string_utf8(env, basicContent->GetText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "text", value);

    // additionalText?: string
    napi_create_string_utf8(env, basicContent->GetAdditionalText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "additionalText", value);

    // lockScreenPicture?: pixelMap
    return SetLockScreenPicture(env, basicContent, result);
}

napi_value Common::SetNotificationLongTextContent(
    const napi_env &env, NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }

    OHOS::Notification::NotificationLongTextContent *longTextContent =
        static_cast<OHOS::Notification::NotificationLongTextContent *>(basicContent);
    if (longTextContent == nullptr) {
        ANS_LOGE("longTextContent is null");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationBasicContent(env, longTextContent, result)) {
        ANS_LOGE("SetNotificationBasicContent call failed");
        return NapiGetBoolean(env, false);
    }

    // longText: string
    napi_create_string_utf8(env, longTextContent->GetLongText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "longText", value);

    // briefText: string
    napi_create_string_utf8(env, longTextContent->GetBriefText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "briefText", value);

    // expandedTitle: string
    napi_create_string_utf8(env, longTextContent->GetExpandedTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "expandedTitle", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationPictureContent(
    const napi_env &env, NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }
    OHOS::Notification::NotificationPictureContent *pictureContent =
        static_cast<OHOS::Notification::NotificationPictureContent *>(basicContent);
    if (pictureContent == nullptr) {
        ANS_LOGE("pictureContent is null");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationBasicContent(env, pictureContent, result)) {
        ANS_LOGE("SetNotificationBasicContent call failed");
        return NapiGetBoolean(env, false);
    }

    // briefText: string
    napi_create_string_utf8(env, pictureContent->GetBriefText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "briefText", value);

    // expandedTitle: string
    napi_create_string_utf8(env, pictureContent->GetExpandedTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "expandedTitle", value);

    // picture: image.PixelMap
    std::shared_ptr<Media::PixelMap> picture = pictureContent->GetBigPicture();
    if (picture) {
        napi_value pictureResult = nullptr;
        napi_valuetype valuetype = napi_undefined;
        pictureResult = Media::PixelMapNapi::CreatePixelMap(env, picture);
        NAPI_CALL(env, napi_typeof(env, pictureResult, &valuetype));
        if (valuetype == napi_undefined) {
            ANS_LOGW("pictureResult is undefined");
            napi_set_named_property(env, result, "picture", NapiGetNull(env));
        } else {
            napi_set_named_property(env, result, "picture", pictureResult);
        }
    }
    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationConversationalContent(const napi_env &env,
    NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }
    OHOS::Notification::NotificationConversationalContent *conversationalContent =
        static_cast<OHOS::Notification::NotificationConversationalContent *>(basicContent);
    if (conversationalContent == nullptr) {
        ANS_LOGE("conversationalContent is null");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationBasicContent(env, conversationalContent, result)) {
        ANS_LOGE("SetNotificationBasicContent call failed");
        return NapiGetBoolean(env, false);
    }

    // conversationTitle: string
    napi_create_string_utf8(env, conversationalContent->GetConversationTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "conversationTitle", value);

    // conversationGroup: boolean
    napi_get_boolean(env, conversationalContent->IsConversationGroup(), &value);
    napi_set_named_property(env, result, "conversationGroup", value);

    // messages: Array<ConversationalMessage>
    napi_value arr = nullptr;
    if (!SetConversationalMessages(env, conversationalContent, arr)) {
        ANS_LOGE("SetConversationalMessages call failed");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "messages", arr);

    // user: MessageUser
    napi_value messageUserResult = nullptr;
    napi_create_object(env, &messageUserResult);
    if (!SetMessageUser(env, conversationalContent->GetMessageUser(), messageUserResult)) {
        ANS_LOGE("SetMessageUser call failed");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "user", messageUserResult);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationMultiLineContent(
    const napi_env &env, NotificationBasicContent *basicContent, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (basicContent == nullptr) {
        ANS_LOGE("basicContent is null");
        return NapiGetBoolean(env, false);
    }
    OHOS::Notification::NotificationMultiLineContent *multiLineContent =
        static_cast<OHOS::Notification::NotificationMultiLineContent *>(basicContent);
    if (multiLineContent == nullptr) {
        ANS_LOGE("multiLineContent is null");
        return NapiGetBoolean(env, false);
    }

    if (!SetNotificationBasicContent(env, multiLineContent, result)) {
        ANS_LOGE("SetNotificationBasicContent call failed");
        return NapiGetBoolean(env, false);
    }

    // briefText: string
    napi_create_string_utf8(env, multiLineContent->GetBriefText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "briefText", value);

    // longTitle: string
    napi_create_string_utf8(env, multiLineContent->GetExpandedTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "longTitle", value);

    // lines: Array<String>
    napi_value arr = nullptr;
    int count = 0;
    napi_create_array(env, &arr);
    for (auto vec : multiLineContent->GetAllLines()) {
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, arr, count, value);
        count++;
    }
    napi_set_named_property(env, result, "lines", arr);

    //lineWantAgents: Array<WantAgent>
    auto lineWantAgents = multiLineContent->GetLineWantAgents();
    if (lineWantAgents.size() > 0) {
        napi_value lineWantAgentsArr = nullptr;
        int lineWantAgentCount = 0;
        for (auto item: lineWantAgents) {
            value = CreateWantAgentByJS(env, item);
            napi_set_element(env, lineWantAgentsArr, lineWantAgentCount++, value);
        }
        napi_set_named_property(env, result, "lineWantAgents", lineWantAgentsArr);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetMessageUser(const napi_env &env, const MessageUser &messageUser, napi_value &result)
{
    ANS_LOGD("enter");

    napi_value value = nullptr;
    // name: string
    napi_create_string_utf8(env, messageUser.GetName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "name", value);

    // key: string
    napi_create_string_utf8(env, messageUser.GetKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "key", value);

    // uri: string
    napi_create_string_utf8(env, messageUser.GetUri().ToString().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "uri", value);

    // isMachine: boolean
    napi_get_boolean(env, messageUser.IsMachine(), &value);
    napi_set_named_property(env, result, "isMachine", value);

    // isUserImportant: boolean
    napi_get_boolean(env, messageUser.IsUserImportant(), &value);
    napi_set_named_property(env, result, "isUserImportant", value);

    // icon?: image.PixelMap
    std::shared_ptr<Media::PixelMap> icon = messageUser.GetPixelMap();
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
    return NapiGetBoolean(env, true);
}

napi_value Common::SetConversationalMessages(const napi_env &env,
    const OHOS::Notification::NotificationConversationalContent *conversationalContent, napi_value &arr)
{
    ANS_LOGD("enter");
    if (!conversationalContent) {
        ANS_LOGE("conversationalContent is null");
        return NapiGetBoolean(env, false);
    }

    int count = 0;
    napi_create_array(env, &arr);
    std::vector<std::shared_ptr<NotificationConversationalMessage>> messages =
        conversationalContent->GetAllConversationalMessages();
    for (auto vec : messages) {
        if (!vec) {
            continue;
        }
        napi_value conversationalMessageResult = nullptr;
        napi_create_object(env, &conversationalMessageResult);
        if (!SetConversationalMessage(env, vec, conversationalMessageResult)) {
            ANS_LOGE("SetConversationalMessage call failed");
            return NapiGetBoolean(env, false);
        }
        napi_set_element(env, arr, count, conversationalMessageResult);
        count++;
    }
    return NapiGetBoolean(env, true);
}

napi_value Common::SetConversationalMessage(const napi_env &env,
    const std::shared_ptr<NotificationConversationalMessage> &conversationalMessage, napi_value &result)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    if (conversationalMessage == nullptr) {
        ANS_LOGE("conversationalMessage is null");
        return NapiGetBoolean(env, false);
    }

    // text: string
    napi_create_string_utf8(env, conversationalMessage->GetText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "text", value);

    // timestamp: number
    napi_create_int64(env, conversationalMessage->GetArrivedTime(), &value);
    napi_set_named_property(env, result, "timestamp", value);

    // sender: MessageUser
    napi_value messageUserResult = nullptr;
    napi_create_object(env, &messageUserResult);
    if (!SetMessageUser(env, conversationalMessage->GetSender(), messageUserResult)) {
        ANS_LOGE("SetMessageUser call failed");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "sender", messageUserResult);

    // mimeType: string
    napi_create_string_utf8(env, conversationalMessage->GetMimeType().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "mimeType", value);

    // uri: string
    napi_create_string_utf8(env, conversationalMessage->GetUri()->ToString().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "uri", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::GetNotificationContent(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_value result = AppExecFwk::GetPropertyValueByPropertyName(env, value, "content", napi_object);
    if (result == nullptr) {
        ANS_LOGE("No content.");
        return nullptr;
    }

    int32_t type = 0;
    if (GetNotificationContentType(env, result, type) == nullptr) {
        return nullptr;
    }
    NotificationContent::Type outType = NotificationContent::Type::NONE;
    if (!AnsEnumUtil::ContentTypeJSToC(ContentType(type), outType)) {
        return nullptr;
    }
    switch (outType) {
        case NotificationContent::Type::BASIC_TEXT:
            if (GetNotificationBasicContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::LONG_TEXT:
            if (GetNotificationLongTextContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::PICTURE:
            if (GetNotificationPictureContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::CONVERSATION:
            if (GetNotificationConversationalContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::MULTILINE:
            if (GetNotificationMultiLineContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
            if (GetNotificationLocalLiveViewContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        case NotificationContent::Type::LIVE_VIEW:
            if (GetNotificationLiveViewContent(env, result, request) == nullptr) {
                return nullptr;
            }
            break;
        default:
            return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationBasicContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, result, "normal", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property normal expected.");
        return nullptr;
    }
    napi_get_named_property(env, result, "normal", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of normal must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    if (normalContent == nullptr) {
        ANS_LOGE("normalContent is null");
        return nullptr;
    }

    if (GetNotificationBasicContentDetailed(env, contentResult, normalContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(normalContent));

    return NapiGetNull(env);
}

napi_value Common::GetNotificationBasicContentDetailed(
    const napi_env &env, const napi_value &contentResult, std::shared_ptr<NotificationBasicContent> basicContent)
{
    ANS_LOGD("enter");

    bool hasProperty = false;
    char commonStr[COMMON_TEXT_SIZE] = {0};
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;

    // title: string
    auto value = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "title", napi_string);
    if (value == nullptr) {
        ANS_LOGE("Failed to get title from js.");
        std::string msg = "Incorrect parameter types. The type of title must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property title is empty");
        std::string msg = "Incorrect parameter. Property title is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    basicContent->SetTitle(shortStr);
    ANS_LOGD("normal::title = %{public}s", shortStr);

    // text: string
    value = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "text", napi_string);
    if (value == nullptr) {
        ANS_LOGE("Failed to get text from js.");
        std::string msg = "Incorrect parameter types. The type of text must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, commonStr, COMMON_TEXT_SIZE - 1, &strLen));
    if (std::strlen(commonStr) == 0) {
        ANS_LOGE("Property text is empty");
        std::string msg = "Incorrect parameter. Property text is empty";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    basicContent->SetText(commonStr);
    ANS_LOGD("normal::text = %{public}s", commonStr);

    // additionalText?: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "additionalText", &hasProperty));
    if (hasProperty) {
        value = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "additionalText", napi_string);
        if (value == nullptr) {
            ANS_LOGE("Failed to get additionalText from js.");
            std::string msg = "Incorrect parameter types. The type of additionalText must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, value, commonStr, COMMON_TEXT_SIZE - 1, &strLen));
        basicContent->SetAdditionalText(commonStr);
        ANS_LOGD("normal::additionalText = %{public}s", commonStr);
    }

    // lockScreenPicture?: pixelMap
    return GetLockScreenPicture(env, contentResult, basicContent);
}

napi_value Common::GetNotificationLongTextContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, result, "longText", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property longText expected.");
        return nullptr;
    }

    napi_get_named_property(env, result, "longText", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of longText must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    std::shared_ptr<OHOS::Notification::NotificationLongTextContent> longContent =
        std::make_shared<OHOS::Notification::NotificationLongTextContent>();
    if (longContent == nullptr) {
        ANS_LOGE("longContent is null");
        return nullptr;
    }

    if (GetNotificationLongTextContentDetailed(env, contentResult, longContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(longContent));

    return NapiGetNull(env);
}

napi_value Common::GetNotificationLongTextContentDetailed(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLongTextContent> &longContent)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value longContentResult = nullptr;
    bool hasProperty = false;
    char commonStr[COMMON_TEXT_SIZE] = {0};
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;

    if (GetNotificationBasicContentDetailed(env, contentResult, longContent) == nullptr) {
        return nullptr;
    }

    // longText: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "longText", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property longText expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "longText", &longContentResult);
    NAPI_CALL(env, napi_typeof(env, longContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of longText must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, longContentResult, commonStr, COMMON_TEXT_SIZE-1, &strLen));
    if (std::strlen(commonStr) == 0) {
        ANS_LOGE("Property longText is empty");
        return nullptr;
    }
    longContent->SetLongText(commonStr);
    ANS_LOGD("longText::longText = %{public}s", commonStr);

    // briefText: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "briefText", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property briefText expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "briefText", &longContentResult);
    NAPI_CALL(env, napi_typeof(env, longContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of briefText must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, longContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property briefText is empty");
        return nullptr;
    }
    longContent->SetBriefText(shortStr);
    ANS_LOGD("longText::briefText = %{public}s", shortStr);

    // expandedTitle: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "expandedTitle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property expandedTitle expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "expandedTitle", &longContentResult);
    NAPI_CALL(env, napi_typeof(env, longContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of expandedTitle must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, longContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property expandedTitle is empty");
        return nullptr;
    }
    longContent->SetExpandedTitle(shortStr);
    ANS_LOGD("longText::expandedTitle = %{public}s", shortStr);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationPictureContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, result, "picture", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property picture expected.");
        return nullptr;
    }
    napi_get_named_property(env, result, "picture", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of picture must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    std::shared_ptr<OHOS::Notification::NotificationPictureContent> pictureContent =
        std::make_shared<OHOS::Notification::NotificationPictureContent>();
    if (pictureContent == nullptr) {
        ANS_LOGE("pictureContent is null");
        return nullptr;
    }
    if (GetNotificationPictureContentDetailed(env, contentResult, pictureContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(pictureContent));

    return NapiGetNull(env);
}

napi_value Common::GetNotificationPictureContentDetailed(const napi_env &env,
    const napi_value &contentResult, std::shared_ptr<OHOS::Notification::NotificationPictureContent> &pictureContent)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value pictureContentResult = nullptr;
    bool hasProperty = false;
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;

    if (GetNotificationBasicContentDetailed(env, contentResult, pictureContent) == nullptr) {
        return nullptr;
    }

    // briefText: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "briefText", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property briefText expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "briefText", &pictureContentResult);
    NAPI_CALL(env, napi_typeof(env, pictureContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of briefText must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, pictureContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property briefText is empty");
        return nullptr;
    }
    pictureContent->SetBriefText(shortStr);

    // expandedTitle: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "expandedTitle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property expandedTitle expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "expandedTitle", &pictureContentResult);
    NAPI_CALL(env, napi_typeof(env, pictureContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of expandedTitle must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, pictureContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property expandedTitle is empty");
        return nullptr;
    }
    pictureContent->SetExpandedTitle(shortStr);

    // picture: image.PixelMap
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "picture", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property picture expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "picture", &pictureContentResult);
    NAPI_CALL(env, napi_typeof(env, pictureContentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of picture must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    pixelMap = Media::PixelMapNapi::GetPixelMap(env, pictureContentResult);
    if (pixelMap == nullptr) {
        ANS_LOGE("Invalid object pixelMap");
        return nullptr;
    }
    pictureContent->SetBigPicture(pixelMap);

    return Common::NapiGetNull(env);
}

napi_value Common::GetNotificationConversationalContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    bool hasProperty = false;
    MessageUser user;

    NAPI_CALL(env, napi_has_named_property(env, result, "conversation", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property conversation expected.");
        return nullptr;
    }
    napi_get_named_property(env, result, "conversation", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of conversation must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (GetNotificationConversationalContentByUser(env, contentResult, user) == nullptr) {
        return nullptr;
    }

    std::shared_ptr<OHOS::Notification::NotificationConversationalContent> conversationalContent =
        std::make_shared<OHOS::Notification::NotificationConversationalContent>(user);
    if (conversationalContent == nullptr) {
        ANS_LOGE("conversationalContent is null");
        return nullptr;
    }

    if (GetNotificationBasicContentDetailed(env, contentResult, conversationalContent) == nullptr) {
        return nullptr;
    }
    if (GetNotificationConversationalContentTitle(env, contentResult, conversationalContent) == nullptr) {
        return nullptr;
    }
    if (GetNotificationConversationalContentGroup(env, contentResult, conversationalContent) == nullptr) {
        return nullptr;
    }
    if (GetNotificationConversationalContentMessages(env, contentResult, conversationalContent) == nullptr) {
        return nullptr;
    }

    request.SetContent(std::make_shared<NotificationContent>(conversationalContent));

    return NapiGetNull(env);
}

napi_value Common::GetNotificationConversationalContentByUser(
    const napi_env &env, const napi_value &contentResult, MessageUser &user)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    // user: MessageUser
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "user", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property user expected.");
        return nullptr;
    }
    napi_value userResult = nullptr;
    napi_get_named_property(env, contentResult, "user", &userResult);
    NAPI_CALL(env, napi_typeof(env, userResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of user must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (!GetMessageUser(env, userResult, user)) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetMessageUser(const napi_env &env, const napi_value &result, MessageUser &messageUser)
{
    ANS_LOGD("enter");

    if (GetMessageUserByString(env, result, messageUser) == nullptr) {
        return nullptr;
    }

    if (GetMessageUserByBool(env, result, messageUser) == nullptr) {
        return nullptr;
    }

    if (GetMessageUserByCustom(env, result, messageUser) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetMessageUserByString(const napi_env &env, const napi_value &result, MessageUser &messageUser)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;

    // name: string
    NAPI_CALL(env, napi_has_named_property(env, result, "name", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property name expected.");
        return nullptr;
    }
    napi_value nameResult = nullptr;
    napi_get_named_property(env, result, "name", &nameResult);
    NAPI_CALL(env, napi_typeof(env, nameResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of name must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, nameResult, str, STR_MAX_SIZE - 1, &strLen));
    messageUser.SetName(str);
    ANS_LOGI("MessageUser::name = %{public}s", str);

    // key: string
    NAPI_CALL(env, napi_has_named_property(env, result, "key", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property key expected.");
        return nullptr;
    }
    napi_value keyResult = nullptr;
    napi_get_named_property(env, result, "key", &keyResult);
    NAPI_CALL(env, napi_typeof(env, keyResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of key must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, keyResult, str, STR_MAX_SIZE - 1, &strLen));
    messageUser.SetKey(str);
    ANS_LOGI("MessageUser::key = %{public}s", str);

    // uri: string
    NAPI_CALL(env, napi_has_named_property(env, result, "uri", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property uri expected.");
        return nullptr;
    }
    napi_value uriResult = nullptr;
    napi_get_named_property(env, result, "uri", &uriResult);
    NAPI_CALL(env, napi_typeof(env, uriResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of uri must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, uriResult, str, STR_MAX_SIZE - 1, &strLen));
    Uri uri(str);
    messageUser.SetUri(uri);

    return NapiGetNull(env);
}

napi_value Common::GetMessageUserByBool(const napi_env &env, const napi_value &result, MessageUser &messageUser)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    // isMachine: boolean
    NAPI_CALL(env, napi_has_named_property(env, result, "isMachine", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property isMachine expected.");
        return nullptr;
    }
    napi_value machineResult = nullptr;
    napi_get_named_property(env, result, "isMachine", &machineResult);
    NAPI_CALL(env, napi_typeof(env, machineResult, &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types. The type of isMachine must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    bool machine = false;
    napi_get_value_bool(env, machineResult, &machine);
    messageUser.SetMachine(machine);

    // isUserImportant: boolean
    NAPI_CALL(env, napi_has_named_property(env, result, "isUserImportant", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property isUserImportant expected.");
        return nullptr;
    }
    napi_value importantResult = nullptr;
    napi_get_named_property(env, result, "isUserImportant", &importantResult);
    NAPI_CALL(env, napi_typeof(env, importantResult, &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types. The type of isUserImportant must be bool.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    bool important = false;
    napi_get_value_bool(env, importantResult, &important);
    messageUser.SetUserAsImportant(important);
    ANS_LOGI("MessageUser::isUserImportant = %{public}d", important);

    return NapiGetNull(env);
}

napi_value Common::GetMessageUserByCustom(const napi_env &env, const napi_value &result, MessageUser &messageUser)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    // icon?: image.PixelMap
    NAPI_CALL(env, napi_has_named_property(env, result, "icon", &hasProperty));
    if (hasProperty) {
        napi_value iconResult = nullptr;
        napi_get_named_property(env, result, "icon", &iconResult);
        NAPI_CALL(env, napi_typeof(env, iconResult, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of icon must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
        pixelMap = Media::PixelMapNapi::GetPixelMap(env, iconResult);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        messageUser.SetPixelMap(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationConversationalContentTitle(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationConversationalContent> &conversationalContent)
{
    ANS_LOGD("enter");
    napi_valuetype valuetype = napi_undefined;
    napi_value conversationalContentResult = nullptr;
    bool hasProperty = false;
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;

    // conversationTitle: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "conversationTitle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property conversationTitle expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "conversationTitle", &conversationalContentResult);
    NAPI_CALL(env, napi_typeof(env, conversationalContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(
        env, conversationalContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    conversationalContent->SetConversationTitle(shortStr);
    ANS_LOGD("conversationTitle = %{public}s", shortStr);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationConversationalContentGroup(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationConversationalContent> &conversationalContent)
{
    ANS_LOGD("enter");
    napi_valuetype valuetype = napi_undefined;
    napi_value conversationalContentResult = nullptr;
    bool hasProperty = false;

    // conversationGroup: boolean
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "conversationGroup", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property conversationGroup expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "conversationGroup", &conversationalContentResult);
    NAPI_CALL(env, napi_typeof(env, conversationalContentResult, &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        return nullptr;
    }
    bool conversationGroup = false;
    napi_get_value_bool(env, conversationalContentResult, &conversationGroup);
    conversationalContent->SetConversationGroup(conversationGroup);
    ANS_LOGI("conversationalText::conversationGroup = %{public}d", conversationGroup);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationConversationalContentMessages(
    const napi_env &env, const napi_value &contentResult,
    std::shared_ptr<OHOS::Notification::NotificationConversationalContent> &conversationalContent)
{
    ANS_LOGD("enter");
    napi_valuetype valuetype = napi_undefined;
    napi_value conversationalContentResult = nullptr;
    bool hasProperty = false;

    // messages: Array<ConversationalMessage>
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "messages", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property messages expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "messages", &conversationalContentResult);
    bool isArray = false;
    napi_is_array(env, conversationalContentResult, &isArray);
    if (!isArray) {
        ANS_LOGE("Property messages is expected to be an array.");
        return nullptr;
    }
    uint32_t length = 0;
    napi_get_array_length(env, conversationalContentResult, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return nullptr;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value conversationalMessage = nullptr;
        napi_get_element(env, conversationalContentResult, i, &conversationalMessage);
        NAPI_CALL(env, napi_typeof(env, conversationalMessage, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        std::shared_ptr<NotificationConversationalMessage> message = nullptr;
        if (!GetConversationalMessage(env, conversationalMessage, message)) {
            return nullptr;
        }
        conversationalContent->AddConversationalMessage(message);
    }

    return NapiGetNull(env);
}

napi_value Common::GetConversationalMessage(const napi_env &env, const napi_value &conversationalMessage,
    std::shared_ptr<NotificationConversationalMessage> &message)
{
    ANS_LOGD("enter");

    if (GetConversationalMessageBasicInfo(env, conversationalMessage, message) == nullptr) {
        return nullptr;
    }
    if (GetConversationalMessageOtherInfo(env, conversationalMessage, message) == nullptr) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetConversationalMessageBasicInfo(const napi_env &env, const napi_value &conversationalMessage,
    std::shared_ptr<NotificationConversationalMessage> &message)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    char commonStr[COMMON_TEXT_SIZE] = {0};
    size_t strLen = 0;
    std::string text;
    int64_t timestamp = 0;
    MessageUser sender;

    // text: string
    NAPI_CALL(env, napi_has_named_property(env, conversationalMessage, "text", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property text expected.");
        return nullptr;
    }
    napi_value textResult = nullptr;
    napi_get_named_property(env, conversationalMessage, "text", &textResult);
    NAPI_CALL(env, napi_typeof(env, textResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, textResult, commonStr, COMMON_TEXT_SIZE - 1, &strLen));
    text = commonStr;
    ANS_LOGI("conversationalMessage::text = %{public}s", commonStr);

    // timestamp: number
    NAPI_CALL(env, napi_has_named_property(env, conversationalMessage, "timestamp", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property timestamp expected.");
        return nullptr;
    }
    napi_value timestampResult = nullptr;
    napi_get_named_property(env, conversationalMessage, "timestamp", &timestampResult);
    NAPI_CALL(env, napi_typeof(env, timestampResult, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        return nullptr;
    }
    napi_get_value_int64(env, timestampResult, &timestamp);
    ANS_LOGI("conversationalMessage::timestamp = %{public}" PRId64, timestamp);

    // sender: MessageUser
    NAPI_CALL(env, napi_has_named_property(env, conversationalMessage, "sender", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property sender expected.");
        return nullptr;
    }
    napi_value senderResult = nullptr;
    napi_get_named_property(env, conversationalMessage, "sender", &senderResult);
    NAPI_CALL(env, napi_typeof(env, senderResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }
    if (!GetMessageUser(env, senderResult, sender)) {
        return nullptr;
    }

    message = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    if (!message) {
        ANS_LOGE("Failed to create NotificationConversationalMessage object");
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetConversationalMessageOtherInfo(const napi_env &env, const napi_value &conversationalMessage,
    std::shared_ptr<NotificationConversationalMessage> &message)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    std::string mimeType;
    std::string uri;

    // mimeType: string
    NAPI_CALL(env, napi_has_named_property(env, conversationalMessage, "mimeType", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property mimeType expected.");
        return nullptr;
    }
    napi_value mimeTypeResult = nullptr;
    napi_get_named_property(env, conversationalMessage, "mimeType", &mimeTypeResult);
    NAPI_CALL(env, napi_typeof(env, mimeTypeResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, mimeTypeResult, str, STR_MAX_SIZE - 1, &strLen));
    mimeType = str;
    ANS_LOGI("conversationalMessage::mimeType = %{public}s", str);

    // uri?: string
    NAPI_CALL(env, napi_has_named_property(env, conversationalMessage, "uri", &hasProperty));
    if (hasProperty) {
        napi_value uriResult = nullptr;
        napi_get_named_property(env, conversationalMessage, "uri", &uriResult);
        NAPI_CALL(env, napi_typeof(env, uriResult, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, uriResult, str, STR_MAX_SIZE - 1, &strLen));
        uri = str;
    }

    std::shared_ptr<Uri> uriPtr = std::make_shared<Uri>(uri);
    message->SetData(mimeType, uriPtr);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationMultiLineContent(
    const napi_env &env, const napi_value &result, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value contentResult = nullptr;
    napi_value multiLineContentResult = nullptr;
    bool hasProperty = false;
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;

    NAPI_CALL(env, napi_has_named_property(env, result, "multiLine", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property multiLine expected.");
        return nullptr;
    }
    napi_get_named_property(env, result, "multiLine", &contentResult);
    NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> multiLineContent =
        std::make_shared<OHOS::Notification::NotificationMultiLineContent>();
    if (multiLineContent == nullptr) {
        ANS_LOGE("multiLineContent is null");
        return nullptr;
    }

    if (GetNotificationBasicContentDetailed(env, contentResult, multiLineContent) == nullptr) {
        return nullptr;
    }

    // briefText: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "briefText", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property briefText expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "briefText", &multiLineContentResult);
    NAPI_CALL(env, napi_typeof(env, multiLineContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, multiLineContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property briefText is empty");
        return nullptr;
    }
    multiLineContent->SetBriefText(shortStr);
    ANS_LOGD("multiLine: briefText = %{public}s", shortStr);

    // longTitle: string
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "longTitle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property longTitle expected.");
        return nullptr;
    }
    napi_get_named_property(env, contentResult, "longTitle", &multiLineContentResult);
    NAPI_CALL(env, napi_typeof(env, multiLineContentResult, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, multiLineContentResult, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
    if (std::strlen(shortStr) == 0) {
        ANS_LOGE("Property longTitle is empty");
        return nullptr;
    }
    multiLineContent->SetExpandedTitle(shortStr);
    ANS_LOGD("multiLine: longTitle = %{public}s", shortStr);

    // lines: Array<String>
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "lines", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property lines expected.");
        return nullptr;
    }
    if (GetNotificationMultiLineContentLines(env, contentResult, multiLineContent) == nullptr) {
        return nullptr;
    }

    // lineWantAgents: Array<WantAgent>
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "lineWantAgents", &hasProperty));
    if (hasProperty) {
        if (GetNotificationContentLineWantAgents(env, contentResult, multiLineContent) == nullptr) {
            return nullptr;
        }
    }

    request.SetContent(std::make_shared<NotificationContent>(multiLineContent));

    ANS_LOGD("end");
    return NapiGetNull(env);
}

napi_value Common::GetNotificationMultiLineContentLines(const napi_env &env, const napi_value &result,
    std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent)
{
    ANS_LOGD("enter");

    bool isArray = false;
    napi_valuetype valuetype = napi_undefined;
    napi_value multilines = nullptr;
    char shortStr[SHORT_TEXT_SIZE] = {0};
    size_t strLen = 0;
    uint32_t length = 0;

    napi_get_named_property(env, result, "lines", &multilines);
    napi_is_array(env, multilines, &isArray);
    if (!isArray) {
        ANS_LOGE("Property lines is expected to be an array.");
        return nullptr;
    }

    napi_get_array_length(env, multilines, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return nullptr;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value line = nullptr;
        napi_get_element(env, multilines, i, &line);
        NAPI_CALL(env, napi_typeof(env, line, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, line, shortStr, SHORT_TEXT_SIZE - 1, &strLen));
        multiLineContent->AddSingleLine(shortStr);
        ANS_LOGI("multiLine: lines : addSingleLine = %{public}s", shortStr);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationContentLineWantAgents(const napi_env &env, const napi_value &result,
    std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent)
{
    ANS_LOGD("GetNotificationContentLineWantAgents enter");

    bool hasProperty;
    bool isArray;
    napi_value value = nullptr;
    napi_valuetype valuetype = napi_undefined;
    std::vector<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> lineWantAgents;
    uint32_t length = 0;

    NAPI_CALL(env, napi_has_named_property(env, result, "lineWantAgents", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, result, "lineWantAgents", &value);
        NAPI_CALL(env, napi_typeof(env, value, &valuetype));
        napi_is_array(env, value, &isArray);
        if (!isArray) {
            ANS_LOGE("lineWantAgents is expected to be an array.");
            std::string msg = "Incorrect parameter types. The type of lineWantAgents must be array.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID);
            return nullptr;
        }
        napi_get_array_length(env, value, &length);
        for (size_t i = 0; i < length; i++) {
            napi_value wantAgentValue;
            napi_get_element(env, value, i, &wantAgentValue);
            NAPI_CALL(env, napi_typeof(env, wantAgentValue, &valuetype));
            if (valuetype != napi_object) {
                ANS_LOGE("Wrong agrument type. Object expected.");
                std::string msg = "Incorrect parameter types. The type of lineWantAgents item must be object.";
                Common::NapiThrow(env, ERROR_PARAM_INVALID);
                return nullptr;
            }
            AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
            napi_unwrap(env, wantAgentValue, (void **)&wantAgent);
            if (wantAgent == nullptr) {
                ANS_LOGE("Invalid object lineWantAgents");
                return nullptr;
            }
            lineWantAgents.push_back(std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgent));
        }
        multiLineContent->SetLineWantAgents(lineWantAgents);
    }

    return NapiGetNull(env);
}

napi_value Common::GetLockScreenPicture(
    const napi_env &env, const napi_value &contentResult, std::shared_ptr<NotificationBasicContent> basicContent)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, contentResult, "lockscreenPicture", &hasProperty));
    if (hasProperty) {
        auto value = AppExecFwk::GetPropertyValueByPropertyName(env, contentResult, "lockscreenPicture", napi_object);
        if (value == nullptr) {
            ANS_LOGE("Failed to get lockScreenPicture from js.");
            std::string msg = "Incorrect parameter types. The type of lockscreenPicture must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, value);
        if (pixelMap == nullptr) {
            ANS_LOGE("Invalid object pixelMap");
            return nullptr;
        }
        basicContent->SetLockScreenPicture(pixelMap);
    }

    return NapiGetNull(env);
}

napi_value Common::SetLockScreenPicture(
    const napi_env &env, const NotificationBasicContent *basicContent, napi_value &result)
{
    if (basicContent->GetLockScreenPicture() == nullptr) {
        return NapiGetBoolean(env, true);
    }

    std::shared_ptr<Media::PixelMap> picture = basicContent->GetLockScreenPicture();
    napi_valuetype valuetype = napi_undefined;
    napi_value pictureValue = Media::PixelMapNapi::CreatePixelMap(env, picture);
    NAPI_CALL(env, napi_typeof(env, pictureValue, &valuetype));
    if (valuetype == napi_undefined) {
        ANS_LOGE("LockScreenPicture is undefined");
        napi_set_named_property(env, result, "lockscreenPicture", NapiGetNull(env));
    } else {
        napi_set_named_property(env, result, "lockscreenPicture", pictureValue);
    }

    return NapiGetBoolean(env, true);
}
}
}
