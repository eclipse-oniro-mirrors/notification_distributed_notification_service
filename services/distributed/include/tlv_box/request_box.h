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
class NotifticationRequestBox : public BoxBase {
public:
    NotifticationRequestBox();
    NotifticationRequestBox(std::shared_ptr<TlvBox> box);
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
    bool SetNotificationAllLines(const std::vector<std::string>& allLines);
    bool SetNotificationBigPicture(const std::shared_ptr<Media::PixelMap>& bigPicture);
    bool SetNotificationActionName(const std::string& actionName);
    bool SetNotificationUserInput(const std::string& userInput);
    bool SetBigIcon(const std::shared_ptr<Media::PixelMap>& bigIcon);
    bool SetOverlayIcon(const std::shared_ptr<Media::PixelMap>& overlayIcon);
    bool SetCommonLiveView(const std::vector<uint8_t>& byteSequence);
    bool SetFinishTime(int64_t time);
    bool SetAutoDeleteTime(int64_t time);

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
    bool GetNotificationAllLines(std::vector<std::string>& allLines) const;
    bool GetNotificationBigPicture(std::shared_ptr<Media::PixelMap>& bigPicture) const;
    bool GetNotificationActionName(std::string& actionName) const;
    bool GetNotificationUserInput(std::string& userInput) const;
    bool GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon) const;
    bool GetOverlayIcon(std::shared_ptr<Media::PixelMap>& overlayIcon) const;
    bool GetCommonLiveView(std::vector<uint8_t>& byteSequence) const;
    bool GetFinishTime(int64_t& time) const;
    bool GetAutoDeleteTime(int64_t& time) const;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H
