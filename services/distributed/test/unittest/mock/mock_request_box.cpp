/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "mock_request_box.h"

#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "distributed_local_config.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
bool MockNotificationRequestBox::GetNotificationHashCode(std::string& hasdCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hasdCode);
}

bool MockNotificationRequestBox::GetSlotType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_SLOT_TYPE, type);
}

bool MockNotificationRequestBox::GetContentType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_CONTENT_TYPE, type);
}

bool MockNotificationRequestBox::GetCreatorBundleName(std::string& bundleName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(BUNDLE_NAME, bundleName);
}

bool MockNotificationRequestBox::GetReminderFlag(int32_t& flag) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_REMINDERFLAG, flag);
}

bool MockNotificationRequestBox::GetNotificationTitle(std::string& title) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_TITLE, title);
}

bool MockNotificationRequestBox::GetNotificationText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_CONTENT, text);
}

bool MockNotificationRequestBox::GetNotificationAdditionalText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_ADDITIONAL_TEXT, text);
}

bool MockNotificationRequestBox::GetNotificationBriefText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_BRIEF_TEXT, text);
}

bool MockNotificationRequestBox::GetNotificationExpandedTitle(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_EXPANDED_TITLE, text);
}

bool MockNotificationRequestBox::GetNotificationLongText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_LONG_TITLE, text);
}

bool MockNotificationRequestBox::GetAllLineLength(int32_t& length) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(ALL_LINES_LENGTH, length);
}

bool MockNotificationRequestBox::GetNotificationAllLines(std::vector<std::string>& allLines) const
{
    int32_t length = 0;
    if (!GetAllLineLength(length)) {
        return false;
    }

    if (length < 0 || length > MAX_LINES_NUM) {
        ANS_LOGD("Invalid lines %{public}d.", length);
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

bool MockNotificationRequestBox::GetNotificationBigPicture(std::shared_ptr<Media::PixelMap>& bigPicture) const
{
    return true;
}

bool MockNotificationRequestBox::GetNotificationActionName(std::string& actionName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_BUTTON_NAME, actionName);
}

bool MockNotificationRequestBox::GetNotificationUserInput(std::string& userInput) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(ACTION_USER_INPUT, userInput);
}

bool MockNotificationRequestBox::GetSmallIcon(std::shared_ptr<Media::PixelMap>& smallIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::vector<uint8_t> buffer;
    bool res = box_->GetBytes(BUNDLE_ICON, buffer);
    ANS_LOGD("GetSmallIcon buffer size: %{public}d", static_cast<int32_t>(buffer.size()));
    if (!res || buffer.size() <= 0) {
        return false;
    }
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(smallIcon, buffer);
    if (smallIcon == nullptr) {
        return false;
    }
    return true;
}

bool MockNotificationRequestBox::GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon, const int32_t deviceType) const
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
        if (!res || buffer.size() <= 0) {
            return false;
        }
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(bigIcon, buffer);
    }
    if (bigIcon == nullptr) {
        return false;
    }
    return true;
}

bool MockNotificationRequestBox::GetOverlayIcon(
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
        if (!res || buffer.size() <= 0) {
            return false;
        }
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(overlayIcon, buffer);
    }
    if (overlayIcon == nullptr) {
        return false;
    }
    return true;
}

bool MockNotificationRequestBox::GetCommonLiveView(std::vector<uint8_t>& byteSequence) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetBytes(NOTIFICATION_COMMON_LIVEVIEW, byteSequence);
}

bool MockNotificationRequestBox::GetFinishTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(FINISH_DEADLINE_TIME, time);
}

bool MockNotificationRequestBox::GetAutoDeleteTime(int64_t& time) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt64Value(AUTO_DELETE_TIME, time);
}

bool MockNotificationRequestBox::GetAppMessageId(std::string& appMessageId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_APP_MESSAGE_ID, appMessageId);
}

bool MockNotificationRequestBox::GetBoxExtendInfo(std::string& extendInfo) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_EXTENDINFO, extendInfo);
}

bool MockNotificationRequestBox::GetReceiverUserId(int32_t& userId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_RECEIVE_USERID, userId);
}
 
bool MockNotificationRequestBox::GetDeviceUserId(int32_t& userId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LOCAL_DEVICE_USERID, userId);
}
 
bool MockNotificationRequestBox::GetDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool MockNotificationRequestBox::GetActionButtonsLength(int32_t& length) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(ACTION_BUTTONS_LENGTH, length);
}

bool MockNotificationRequestBox::GetActionButtonsTitle(std::vector<std::string>& buttonsTitle) const
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t length = 0;
    if (!GetActionButtonsLength(length) || length > NotificationConstant::MAX_BTN_NUM) {
        return false;
    }
    for (int i = 0; i < length; i++) {
        std::string buttonTitle = "";
        box_->GetStringValue(ACTION_BUTTONS_TITILE_INDEX + i, buttonTitle);
        buttonsTitle.push_back(buttonTitle);
    }
    return true;
}

bool MockNotificationRequestBox::GetNotificationBasicInfo(std::string& basicInfo) const
{
    if (box_ == nullptr) {
        return false;
    }
 
    return box_->GetStringValue(NOTIFICATION_BASIC_INFO, basicInfo);
}
}
}