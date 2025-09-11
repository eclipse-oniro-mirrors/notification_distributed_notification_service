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

#ifndef MOCK_REQUEST_BOX_H
#define MOCK_REQUEST_BOX_H

#include <vector>
#include <string>
#include <map>
#include "pixel_map.h"
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {
class MockNotificationRequestBox : public BoxBase {
public:
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
    bool GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon, const int32_t deviceType) const;
    bool GetOverlayIcon(std::shared_ptr<Media::PixelMap>& overlayIcon, const int32_t deviceType) const;
    bool GetCommonLiveView(std::vector<uint8_t>& byteSequence) const;
    bool GetFinishTime(int64_t& time) const;
    bool GetAutoDeleteTime(int64_t& time) const;
    bool GetAppMessageId(std::string& appMessageId) const;
    bool GetReceiverUserId(int32_t& userId) const;
    bool GetBoxExtendInfo(std::string& extendInfo) const;
    bool GetDeviceUserId(int32_t& userId) const;
    bool GetDeviceId(std::string& deviceId) const;
    bool GetActionButtonsLength(int32_t& length) const;
    bool GetActionButtonsTitle(std::vector<std::string>& buttonsTitle) const;
    bool GetNotificationBasicInfo(std::string& basicInfo) const;

    static const int32_t MAX_LINES_NUM = 7;
};
}  // namespace Notification
}  // namespace OHOS
#endif // MOCK_REQUEST_BOX_H