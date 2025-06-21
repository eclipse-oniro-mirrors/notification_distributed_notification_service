/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_REQUEST_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_REQUEST_BOX_H

#include <vector>
#include <string>
#include <map>
#include "pixel_map.h"
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {
class NotificationRequestBox : public BoxBase {
public:
    NotificationRequestBox();
    NotificationRequestBox(std::shared_ptr<TlvBox> box);
#ifdef DISTRIBUTED_FEATURE_MASTER
    bool SetNotificationHashCode(const std::string& hasdCode);
    bool SetSlotType(int32_t type);
    bool SetContentType(int32_t type);
    bool SetReminderFlag(int32_t flag);
    bool SetCreatorBundleName(const std::string& bundleName);
    bool SetNotificationTitle(const std::string& title);
    bool SetNotificationText(const std::string& text);
    bool SetNotificationAdditionalText(const std::string& text);
    bool SetNotificationBriefText(const std::string& text);
    bool SetNotificationExpandedTitle(const std::string& text);
    bool SetNotificationLongText(const std::string& text);
    bool SetAllLineLength(const int32_t& length);
    bool SetNotificationAllLines(const std::vector<std::string>& allLines);
    bool SetNotificationBigPicture(const std::shared_ptr<Media::PixelMap>& bigPicture);
    bool SetNotificationActionName(const std::string& actionName);
    bool SetNotificationUserInput(const std::string& userInput);
    bool SetSmallIcon(const std::shared_ptr<Media::PixelMap>& smallIcon);
    bool SetBigIcon(const std::shared_ptr<Media::PixelMap>& bigIcon, int32_t deviceType);
    bool SetOverlayIcon(const std::shared_ptr<Media::PixelMap>& overlayIcon, int32_t deviceType);
    bool SetCommonLiveView(const std::vector<uint8_t>& byteSequence);
    bool SetFinishTime(int64_t time);
    bool SetAutoDeleteTime(int64_t time);
    bool SetAppMessageId(const std::string& appMessageId);
    bool SetAppIcon(const std::string& appIcon);
    bool SetAppName(const std::string& appName);
    bool SetAppLabel(const std::string& appLabel);
    bool SetAppIndex(const int32_t& appIndex);
    bool SetNotificationUserId(const int32_t& userId);
    bool SetDeviceUserId(const int32_t& userId);
    bool SetDeviceId(const std::string& deviceId);
    bool SetActionButtonsLength(const int32_t length);
    bool SetActionButtonsTitle(const std::vector<std::string>& buttonsTitle);
    bool SetActionUserInputs(const std::vector<std::string>& userInputs);
#else
    bool GetNotificationHashCode(std::string& hasdCode) const;
    bool GetSlotType(int32_t& type) const;
    bool GetContentType(int32_t& type) const;
    bool GetReminderFlag(int32_t& flag) const;
    bool GetCreatorBundleName(std::string& bundleName) const;
    bool GetNotificationTitle(std::string& title) const;
    bool GetNotificationText(std::string& text) const;
    bool GetNotificationAdditionalText(std::string& text) const;
    bool GetNotificationBriefText(std::string& text) const;
    bool GetNotificationExpandedTitle(std::string& text) const;
    bool GetNotificationLongText(std::string& text) const;
    bool GetAllLineLength(int32_t& length) const;
    bool GetNotificationAllLines(std::vector<std::string>& allLines) const;
    bool GetNotificationBigPicture(std::shared_ptr<Media::PixelMap>& bigPicture) const;
    bool GetNotificationActionName(std::string& actionName) const;
    bool GetNotificationUserInput(std::string& userInput) const;
    bool GetSmallIcon(std::shared_ptr<Media::PixelMap>& smallIcon) const;
    bool GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon) const;
    bool GetOverlayIcon(std::shared_ptr<Media::PixelMap>& overlayIcon) const;
    bool GetCommonLiveView(std::vector<uint8_t>& byteSequence) const;
    bool GetFinishTime(int64_t& time) const;
    bool GetAutoDeleteTime(int64_t& time) const;
    bool GetAppMessageId(std::string& appMessageId) const;
    bool GetAppIcon(std::string& appIcon) const;
    bool GetAppName(std::string& appName) const;
    bool GetAppLabel(std::string& appLabel) const;
    bool GetAppIndex(int32_t& appIndex) const;
    bool GetNotificationUserId(int32_t& userId) const;
    bool GetDeviceUserId(int32_t& userId) const;
    bool GetDeviceId(std::string& deviceId) const;
    bool GetActionButtonsLength(int32_t& length) const;
    bool GetActionButtonsTitle(std::vector<std::string>& buttonsTitle) const;
    bool GetActionUserInputs(std::vector<std::string>& userInputs) const;
#endif
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H
