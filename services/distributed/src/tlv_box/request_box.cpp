/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "request_box.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "distributed_local_config.h"

namespace OHOS {
namespace Notification {

NotificationRequestBox::NotificationRequestBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(PUBLISH_NOTIFICATION);
}

NotificationRequestBox::NotificationRequestBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

#ifdef DISTRIBUTED_FEATURE_MASTER
bool NotificationRequestBox::SetNotificationHashCode(const std::string& hasdCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hasdCode));
}

bool NotificationRequestBox::SetSlotType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_SLOT_TYPE, type));
}

bool NotificationRequestBox::SetContentType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT_TYPE, type));
}

bool NotificationRequestBox::SetAppMessageId(const std::string& appMessageId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_APP_MESSAGE_ID, appMessageId));
}

bool NotificationRequestBox::SetReminderFlag(int32_t flag)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_REMINDERFLAG, flag));
}

bool NotificationRequestBox::SetCreatorBundleName(const std::string& bundleName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_NAME, bundleName));
}

bool NotificationRequestBox::SetNotificationTitle(const std::string& title)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetTitleLength());
    if (title.size() > maxLength) {
        ANS_LOGI("SetNotificationTitle truncate %{public}zu %{public}u", title.size(), maxLength);
        std::string subTitle =  title.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subTitle.c_str(), title.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, subTitle));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, title));
}

bool NotificationRequestBox::SetNotificationText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetContentLength());
    if (text.size() > maxLength) {
        ANS_LOGI("SetNotificationText truncate %{public}zu %{public}u", text.size(), maxLength);
        std::string subText =  text.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subText.c_str(), text.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, subText));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, text));
}

bool NotificationRequestBox::SetNotificationAdditionalText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_ADDITIONAL_TEXT, text));
}

bool NotificationRequestBox::SetNotificationBriefText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BRIEF_TEXT, text));
}

bool NotificationRequestBox::SetNotificationExpandedTitle(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_EXPANDED_TITLE, text));
}

bool NotificationRequestBox::SetNotificationLongText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_LONG_TITLE, text));
}

bool NotificationRequestBox::SetAllLineLength(const int32_t& length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ALL_LINES_LENGTH, length));
}

bool NotificationRequestBox::SetNotificationAllLines(const std::vector<std::string>& allLines)
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t index = 0;
    for (auto& line : allLines) {
        if (box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_ALL_LINES_START_INDEX + index, line))) {
            index++;
        }
    }
    return SetAllLineLength(index);
}

bool NotificationRequestBox::SetNotificationBigPicture(const std::shared_ptr<Media::PixelMap>& bigPicture)
{
    return true;
}

bool NotificationRequestBox::SetNotificationActionName(const std::string& actionName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_BUTTON_NAME, actionName));
}

bool NotificationRequestBox::SetNotificationUserInput(const std::string& userInput)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_USER_INPUT, userInput));
}

bool NotificationRequestBox::SetSmallIcon(const std::shared_ptr<Media::PixelMap>& smallIcon)
{
    if (box_ == nullptr) {
        return false;
    }
    std::vector<uint8_t> buffer;
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(smallIcon, buffer);
    ANS_LOGD("SetSmallIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
    const unsigned char* begin = buffer.data();
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_ICON, begin, buffer.size()));
}

bool NotificationRequestBox::SetBigIcon(const std::shared_ptr<Media::PixelMap>& bigIcon,
    int32_t deviceType)
{
    if (box_ == nullptr) {
        return false;
    }

    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        std::string icon;
        std::string copyIcon = AnsImageUtil::PackImage(bigIcon);
        auto copyPixelMap = AnsImageUtil::UnPackImage(copyIcon);
        if (!AnsImageUtil::ImageScale(copyPixelMap, DEFAULT_ICON_WITHE, DEFAULT_ICON_HEIGHT)) {
            return false;
        }
        icon = AnsImageUtil::PackImage(copyPixelMap);
        ANS_LOGD("SetBigIcon %{public}zu, %{public}zu", copyIcon.size(), icon.size());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BIG_ICON, icon));
    }
    std::vector<uint8_t> buffer;
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(bigIcon, buffer);
    ANS_LOGD("SetBigIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
    const unsigned char* begin = buffer.data();
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BIG_ICON, begin, buffer.size()));
}

bool NotificationRequestBox::SetOverlayIcon(const std::shared_ptr<Media::PixelMap>& overlayIcon,
    int32_t deviceType)
{
    if (box_ == nullptr) {
        return false;
    }

    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        std::string icon;
        std::string copyIcon = AnsImageUtil::PackImage(overlayIcon);
        auto copyPixelMap = AnsImageUtil::UnPackImage(copyIcon);
        if (!AnsImageUtil::ImageScale(copyPixelMap, DEFAULT_ICON_WITHE, DEFAULT_ICON_HEIGHT)) {
            return false;
        }
        icon = AnsImageUtil::PackImage(copyPixelMap);
        ANS_LOGD("SetOverlayIcon %{public}zu, %{public}zu", copyIcon.size(), icon.size());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_OVERLAY_ICON, icon));
    }
    std::vector<uint8_t> buffer;
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(overlayIcon, buffer);
    ANS_LOGD("SetOverlayIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
    const unsigned char* begin = buffer.data();
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_OVERLAY_ICON, begin, buffer.size()));
}

bool NotificationRequestBox::SetCommonLiveView(const std::vector<uint8_t>& byteSequence)
{
    if (box_ == nullptr) {
        return false;
    }
    const unsigned char* begin = byteSequence.data();
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_COMMON_LIVEVIEW,
        begin, byteSequence.size()));
}

bool NotificationRequestBox::SetFinishTime(int64_t time)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(FINISH_DEADLINE_TIME, time));
}

bool NotificationRequestBox::SetAutoDeleteTime(int64_t time)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(AUTO_DELETE_TIME, time));
}


bool NotificationRequestBox::SetReceiverUserId(const int32_t& userId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_RECEIVE_USERID, userId));
}

bool NotificationRequestBox::SetBoxExtendInfo(const std::string& extendInfo)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_EXTENDINFO, extendInfo));
}

bool NotificationRequestBox::SetDeviceUserId(const int32_t& userId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_USERID, userId));
}

bool NotificationRequestBox::SetDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool NotificationRequestBox::SetActionButtonsLength(const int32_t length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(ACTION_BUTTONS_LENGTH, length));
}

bool NotificationRequestBox::SetActionButtonsTitle(const std::vector<std::string>& buttonsTitle)
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t index = 0;
    for (auto& buttonTitle : buttonsTitle) {
        if (box_->PutValue(
            std::make_shared<TlvItem>(ACTION_BUTTONS_TITILE_INDEX + index, buttonTitle))) {
            index++;
        }
    }
    return SetActionButtonsLength(index);
}

bool NotificationRequestBox::SetNotificationBasicInfo(const std::string& basicInfo)
{
    if (box_ == nullptr) {
        return false;
    }
    box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BASIC_INFO, basicInfo));
    return true;
}
#else
bool NotificationRequestBox::GetNotificationHashCode(std::string& hasdCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hasdCode);
}

bool NotificationRequestBox::GetSlotType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_SLOT_TYPE, type);
}

bool NotificationRequestBox::GetContentType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_CONTENT_TYPE, type);
}

bool NotificationRequestBox::GetCreatorBundleName(std::string& bundleName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(BUNDLE_NAME, bundleName);
}

bool NotificationRequestBox::GetReminderFlag(int32_t& flag) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_REMINDERFLAG, flag);
}

bool NotificationRequestBox::GetNotificationTitle(std::string& title) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_TITLE, title);
}

bool NotificationRequestBox::GetNotificationText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_CONTENT, text);
}

bool NotificationRequestBox::GetNotificationAdditionalText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_ADDITIONAL_TEXT, text);
}

bool NotificationRequestBox::GetNotificationBriefText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_BRIEF_TEXT, text);
}

bool NotificationRequestBox::GetNotificationExpandedTitle(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_EXPANDED_TITLE, text);
}

bool NotificationRequestBox::GetNotificationLongText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_LONG_TITLE, text);
}

bool NotificationRequestBox::GetAllLineLength(int32_t& length) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(ALL_LINES_LENGTH, length);
}

bool NotificationRequestBox::GetNotificationAllLines(std::vector<std::string>& allLines) const
{
    int32_t length = 0;
    if (!GetAllLineLength(length)) {
        return false;
    }
    for (int i = 0; i < length; i++) {
        std::string line;
        if (box_->GetStringValue(NOTIFICATION_ALL_LINES_START_INDEX + i, line)) {
            allLines.push_back(line);
        }
    }
    return true;
}

bool NotificationRequestBox::GetNotificationBigPicture(std::shared_ptr<Media::PixelMap>& bigPicture) const
{
    return true;
}

bool NotificationRequestBox::GetNotificationActionName(std::string& actionName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_BUTTON_NAME, actionName);
}

bool NotificationRequestBox::GetNotificationUserInput(std::string& userInput) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_USER_INPUT, userInput);
}

bool NotificationRequestBox::GetSmallIcon(std::shared_ptr<Media::PixelMap>& smallIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::vector<uint8_t> buffer;
    bool res = box_->GetBytes(BUNDLE_ICON, buffer);
    ANS_LOGD("GetSmallIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(smallIcon, buffer);
    if (smallIcon == nullptr) {
        return false;
    }
    return true;
}

bool NotificationRequestBox::GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon, const int32_t deviceType) const
{
    if (box_ == nullptr) {
        return false;
    }
    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        std::string bigIconContent;
        if (!box_->GetStringValue(NOTIFICATION_BIG_ICON, bigIconContent)) {
            return false;
        }
        ANS_LOGD("GetBigIcon %{public}zu", bigIconContent.size());
        bigIcon = AnsImageUtil::UnPackImage(bigIconContent);
    } else {
        std::vector<uint8_t> buffer;
        bool res = box_->GetBytes(NOTIFICATION_BIG_ICON, buffer);
        ANS_LOGD("GetBigIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(bigIcon, buffer);
    }
    if (bigIcon == nullptr) {
        return false;
    }
    return true;
}

bool NotificationRequestBox::GetOverlayIcon(
    std::shared_ptr<Media::PixelMap>& overlayIcon, const int32_t deviceType) const
{
    if (box_ == nullptr) {
        return false;
    }
    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        std::string overlayContent;
        if (!box_->GetStringValue(NOTIFICATION_OVERLAY_ICON, overlayContent)) {
            return false;
        }
        ANS_LOGD("GetOverlayIcon %{public}zu", overlayContent.size());
        overlayIcon = AnsImageUtil::UnPackImage(overlayContent);
    } else {
        std::vector<uint8_t> buffer;
        bool res = box_->GetBytes(NOTIFICATION_OVERLAY_ICON, buffer);
        ANS_LOGD("GetOverlayIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(overlayIcon, buffer);
    }
    if (overlayIcon == nullptr) {
        return false;
    }
    return true;
}

bool NotificationRequestBox::GetCommonLiveView(std::vector<uint8_t>& byteSequence) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetBytes(NOTIFICATION_COMMON_LIVEVIEW, byteSequence);
}

bool NotificationRequestBox::GetFinishTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(FINISH_DEADLINE_TIME, time);
}

bool NotificationRequestBox::GetAutoDeleteTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(AUTO_DELETE_TIME, time);
}

bool NotificationRequestBox::GetAppMessageId(std::string& appMessageId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_APP_MESSAGE_ID, appMessageId);
}

bool NotificationRequestBox::GetBoxExtendInfo(std::string& extendInfo) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_EXTENDINFO, extendInfo);
}

bool NotificationRequestBox::GetReceiverUserId(int32_t& userId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_RECEIVE_USERID, userId);
}

bool NotificationRequestBox::GetDeviceUserId(int32_t& userId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LOCAL_DEVICE_USERID, userId);
}

bool NotificationRequestBox::GetDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool NotificationRequestBox::GetActionButtonsLength(int32_t& length) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(ACTION_BUTTONS_LENGTH, length);
}

bool NotificationRequestBox::GetActionButtonsTitle(std::vector<std::string>& buttonsTitle) const
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t length = 0;
    if (!GetActionButtonsLength(length)) {
        return false;
    }
    for (int i = 0; i < length; i++) {
        std::string buttonTitle = "";
        box_->GetStringValue(ACTION_BUTTONS_TITILE_INDEX + i, buttonTitle);
        buttonsTitle.push_back(buttonTitle);
    }
    return true;
}

bool NotificationRequestBox::GetNotificationBasicInfo(std::string& basicInfo) const
{
    if (box_ == nullptr) {
        return false;
    }
    box_->GetStringValue(NOTIFICATION_BASIC_INFO, basicInfo);
    return true;
}
#endif
}
}

