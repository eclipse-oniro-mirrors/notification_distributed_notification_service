/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "notification_content.h"
#include "ans_log_wrapper.h"
#include "notification_local_live_view_content.h"

namespace OHOS {
namespace Notification {
std::map<std::string, NotificationContent::Type> NotificationContent::convertStrToContentType_;

NotificationContent::NotificationContent(const std::shared_ptr<NotificationNormalContent> &normalContent)
{
    if (!normalContent) {
        ANS_LOGE("null normalContent");
        return;
    }

    contentType_ = NotificationContent::Type::BASIC_TEXT;
    content_ = normalContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationLongTextContent> &longTextContent)
{
    if (!longTextContent) {
        ANS_LOGE("null longTextContent");
        return;
    }

    contentType_ = NotificationContent::Type::LONG_TEXT;
    content_ = longTextContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationPictureContent> &pictureContent)
{
    if (!pictureContent) {
        ANS_LOGE("null pictureContent");
        return;
    }

    contentType_ = NotificationContent::Type::PICTURE;
    content_ = pictureContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationConversationalContent> &conversationContent)
{
    if (!conversationContent) {
        ANS_LOGE("null conversationContent");
        return;
    }

    contentType_ = NotificationContent::Type::CONVERSATION;
    content_ = conversationContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationMultiLineContent> &multiLineContent)
{
    if (!multiLineContent) {
        ANS_LOGE("null multiLineContent");
        return;
    }

    contentType_ = NotificationContent::Type::MULTILINE;
    content_ = multiLineContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationMediaContent> &mediaContent)
{
    if (!mediaContent) {
        ANS_LOGE("null mediaContent");
        return;
    }

    contentType_ = NotificationContent::Type::MEDIA;
    content_ = mediaContent;
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent)
{
    if (!localLiveViewContent) {
        ANS_LOGE("null localLiveViewContent");
        return;
    }

    contentType_ = NotificationContent::Type::LOCAL_LIVE_VIEW;
    content_ = localLiveViewContent;
    content_->SetContentType(static_cast<int32_t>(NotificationContent::Type::LOCAL_LIVE_VIEW));
}

NotificationContent::NotificationContent(const std::shared_ptr<NotificationLiveViewContent> &liveViewContent)
{
    if (!liveViewContent) {
        ANS_LOGE("null liveViewContent");
        return;
    }

    contentType_ = NotificationContent::Type::LIVE_VIEW;
    content_ = liveViewContent;
}

NotificationContent::~NotificationContent()
{}

NotificationContent::Type NotificationContent::GetContentType() const
{
    return contentType_;
}

std::shared_ptr<NotificationBasicContent> NotificationContent::GetNotificationContent() const
{
    return content_;
}

std::string NotificationContent::Dump()
{
    std::string contentTypeStr =   (contentType_ == NotificationContent::Type::BASIC_TEXT)          ? "BASIC_TEXT"
                                 : (contentType_ == NotificationContent::Type::CONVERSATION)        ? "CONVERSATION"
                                 : (contentType_ == NotificationContent::Type::LONG_TEXT)           ? "LONG_TEXT"
                                 : (contentType_ == NotificationContent::Type::MEDIA)               ? "MEDIA"
                                 : (contentType_ == NotificationContent::Type::MULTILINE)           ? "MULTILINE"
                                 : (contentType_ == NotificationContent::Type::PICTURE)             ? "PICTURE"
                                 : (contentType_ == NotificationContent::Type::LOCAL_LIVE_VIEW)     ? "LOCAL_LIVE_VIEW"
                                 : (contentType_ == NotificationContent::Type::LIVE_VIEW)           ? "LIVE_VIEW"
                                 : "NONE";
    return "NotificationContent{ "
            "contentType = " + contentTypeStr +
            ", content = " + (content_ ? content_->Dump() : "null") +
            " }";
}

bool NotificationContent::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["contentType"] = static_cast<int32_t>(contentType_);
    jsonObject["notificationContentType"] = static_cast<int32_t>(contentType_);

    if (!content_) {
        ANS_LOGE("Invalid content. Cannot convert to JSON.");
        return false;
    }

    nlohmann::json contentObj;
    if (!NotificationJsonConverter::ConvertToJson(content_.get(), contentObj)) {
        ANS_LOGE("Cannot convert content to JSON");
        return false;
    }
    jsonObject["content"] = contentObj;

    return true;
}

NotificationContent *NotificationContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }
    const auto &jsonEnd = jsonObject.cend();
    if ((jsonObject.find("contentType") == jsonEnd) || (jsonObject.find("content") == jsonEnd)) {
        ANS_LOGE("Cannot convert content from JSON");
        return nullptr;
    }

    auto pContent = new (std::nothrow) NotificationContent();
    if (pContent == nullptr) {
        ANS_LOGE("null pContent");
        return nullptr;
    }

    if (!ConvertJsonToContent(pContent, jsonObject)) {
        delete pContent;
        pContent = nullptr;
        return nullptr;
    }

    return pContent;
}

bool NotificationContent::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(contentType_))) {
        ANS_LOGE("Failed to write contentType");
        return false;
    }

    auto valid = content_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether content is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(content_.get())) {
            ANS_LOGE("Failed to write content");
            return false;
        }
    }

    return true;
}

NotificationContent *NotificationContent::Unmarshalling(Parcel &parcel)
{
    auto pContent = new (std::nothrow) NotificationContent();
    if ((pContent != nullptr) && !pContent->ReadFromParcel(parcel)) {
        delete pContent;
        pContent = nullptr;
    }

    return pContent;
}

bool NotificationContent::ReadFromParcel(Parcel &parcel)
{
    contentType_ = static_cast<NotificationContent::Type>(parcel.ReadInt32());

    if (!parcel.ReadBool()) {
        return true;
    }

    switch (contentType_) {
        case NotificationContent::Type::BASIC_TEXT:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationNormalContent>(parcel.ReadParcelable<NotificationNormalContent>()));
            break;
        case NotificationContent::Type::CONVERSATION:
            content_ =
                std::static_pointer_cast<NotificationBasicContent>(std::shared_ptr<NotificationConversationalContent>(
                    parcel.ReadParcelable<NotificationConversationalContent>()));
            break;
        case NotificationContent::Type::LONG_TEXT:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationLongTextContent>(parcel.ReadParcelable<NotificationLongTextContent>()));
            break;
        case NotificationContent::Type::MEDIA:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationMediaContent>(parcel.ReadParcelable<NotificationMediaContent>()));
            break;
        case NotificationContent::Type::MULTILINE:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationMultiLineContent>(parcel.ReadParcelable<NotificationMultiLineContent>()));
            break;
        case NotificationContent::Type::PICTURE:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationPictureContent>(parcel.ReadParcelable<NotificationPictureContent>()));
            break;
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationLocalLiveViewContent>(
                    parcel.ReadParcelable<NotificationLocalLiveViewContent>()));
            break;
        case NotificationContent::Type::LIVE_VIEW:
            content_ = std::static_pointer_cast<NotificationBasicContent>(
                std::shared_ptr<NotificationLiveViewContent>(parcel.ReadParcelable<NotificationLiveViewContent>()));
            break;
        default:
            ANS_LOGE("Invalid contentType");
            return false;
    }
    if (!content_) {
        ANS_LOGE("Failed to read content");
        return false;
    }

    return true;
}

bool NotificationContent::ConvertJsonToContent(NotificationContent *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("null target");
        return false;
    }

    auto contentType  = jsonObject.at("contentType");
    if (!contentType.is_number_integer()) {
        ANS_LOGE("ContentType is not integer");
        return false;
    }
    target->contentType_   = static_cast<NotificationContent::Type>(contentType.get<int32_t>());

    auto contentObj = jsonObject.at("content");
    if (contentObj.is_null()) {
        ANS_LOGE("Cannot convert content from JSON");
        return false;
    }

    NotificationBasicContent *pBasicContent {nullptr};
    switch (target->contentType_) {
        case NotificationContent::Type::BASIC_TEXT:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationNormalContent>(contentObj);
            break;
        case NotificationContent::Type::CONVERSATION:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationConversationalContent>(contentObj);
            break;
        case NotificationContent::Type::LONG_TEXT:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationLongTextContent>(contentObj);
            break;
        case NotificationContent::Type::MULTILINE:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationMultiLineContent>(contentObj);
            break;
        case NotificationContent::Type::PICTURE:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationPictureContent>(contentObj);
            break;
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationLocalLiveViewContent>(contentObj);
            break;
        case NotificationContent::Type::LIVE_VIEW:
            pBasicContent = NotificationJsonConverter::ConvertFromJson<NotificationLiveViewContent>(contentObj);
            break;
        default:
            ANS_LOGE("Invalid contentType");
            break;
    }
    if (pBasicContent == nullptr) {
        ANS_LOGE("null pBasicContent");
        return false;
    }
    target->content_ = std::shared_ptr<NotificationBasicContent>(pBasicContent);

    return true;
}

bool NotificationContent::GetContentTypeByString(
    const std::string &strContentType, NotificationContent::Type &contentType)
{
    if (convertStrToContentType_.size() <= 0) {
        convertStrToContentType_[CONTENT_TYPE_NONE] = NotificationContent::Type::NONE;
        convertStrToContentType_[CONTENT_TYPE_BASIC_TEXT] = NotificationContent::Type::BASIC_TEXT;
        convertStrToContentType_[CONTENT_TYPE_CONVERSATION] = NotificationContent::Type::CONVERSATION;
        convertStrToContentType_[CONTENT_TYPE_LONG_TEXT] = NotificationContent::Type::LONG_TEXT;
        convertStrToContentType_[CONTENT_TYPE_MEDIA] = NotificationContent::Type::MEDIA;
        convertStrToContentType_[CONTENT_TYPE_MULTILINE] = NotificationContent::Type::MULTILINE;
        convertStrToContentType_[CONTENT_TYPE_PICTURE] = NotificationContent::Type::PICTURE;
        convertStrToContentType_[CONTENT_TYPE_LOCAL_LIVE_VIEW] = NotificationContent::Type::LOCAL_LIVE_VIEW;
        convertStrToContentType_[CONTENT_TYPE_LIVE_VIEW] = NotificationContent::Type::LIVE_VIEW;
    }
    auto iterContentType = convertStrToContentType_.find(strContentType);
    if (iterContentType != convertStrToContentType_.end()) {
        contentType = iterContentType->second;
        return true;
    }
    ANS_LOGE("Invalid strContentType");
    return false;
}
}  // namespace Notification
}  // namespace OHOS
