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
#include "distributed_local_config.h"

namespace OHOS {
namespace Notification {

NotifticationRequestBox::NotifticationRequestBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(PUBLISH_NOTIFICATION);
}

NotifticationRequestBox::NotifticationRequestBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotifticationRequestBox::SetNotificationHashCode(const std::string& hasdCode)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, hasdCode));
}

bool NotifticationRequestBox::SetSlotType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_SLOT_TYPE, type));
}

bool NotifticationRequestBox::SetContentType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT_TYPE, type));
}

bool NotifticationRequestBox::SetReminderFlag(int32_t flag)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_REMINDERFLAG, flag));
}

bool NotifticationRequestBox::SetCreatorBundleName(const std::string& bundleName)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_NAME, bundleName));
}

bool NotifticationRequestBox::SetNotificationTitle(const std::string& title)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetTitleLength());
    if (title.size() > maxLength) {
        ANS_LOGI("SetNotificationTitle truncate %{public}u %{public}u", title.size(), maxLength);
        std::string subTitle =  title.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subTitle.c_str(), title.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, subTitle));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_TITLE, title));
}

bool NotifticationRequestBox::SetNotificationText(const std::string& text)
{
    if (box_ == nullptr) {
        return false;
    }
    uint32_t maxLength = static_cast<uint32_t>(DistributedLocalConfig::GetInstance().GetContentLength());
    if (text.size() > maxLength) {
        ANS_LOGI("SetNotificationText truncate %{public}u %{public}u", text.size(), maxLength);
        std::string subText =  text.substr(0, maxLength);
        ANS_LOGI("SetNotificationTitle truncate %{public}s %{public}s", subText.c_str(), text.c_str());
        return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, subText));
    }
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_CONTENT, text));
}

bool NotifticationRequestBox::SetBigIcon(const std::shared_ptr<Media::PixelMap>& bigIcon)
{
    if (box_ == nullptr) {
        return false;
    }
    std::string icon = AnsImageUtil::PackImage(bigIcon);
    ANS_LOGI("SetBigIcon %{public}s", icon.c_str());
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_BIG_ICON, icon));
}

bool NotifticationRequestBox::SetOverlayIcon(const std::shared_ptr<Media::PixelMap>& overlayIcon)
{
    if (box_ == nullptr) {
        return false;
    }
    std::string icon = AnsImageUtil::PackImage(overlayIcon);
    ANS_LOGI("SetOverlayIcon %{public}s", icon.c_str());
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_OVERLAY_ICON, icon));
}

bool NotifticationRequestBox::SetCommonLiveView(const std::vector<uint8_t>& byteSequence)
{
    if (box_ == nullptr) {
        return false;
    }
    const unsigned char* begin = byteSequence.data();
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_COMMON_LIVEVIEW,
        begin, byteSequence.size()));
}

bool NotifticationRequestBox::GetNotificationHashCode(std::string& hasdCode) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_HASHCODE, hasdCode);
}

bool NotifticationRequestBox::GetSlotType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_SLOT_TYPE, type);
}

bool NotifticationRequestBox::GetContentType(int32_t& type) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_CONTENT_TYPE, type);
}

bool NotifticationRequestBox::GetCreatorBundleName(std::string& bundleName) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(BUNDLE_NAME, bundleName);
}

bool NotifticationRequestBox::GetReminderFlag(int32_t& flag) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(NOTIFICATION_REMINDERFLAG, flag);
}

bool NotifticationRequestBox::GetNotificationTitle(std::string& title) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_TITLE, title);
}

bool NotifticationRequestBox::GetNotificationText(std::string& text) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(NOTIFICATION_CONTENT, text);
}

bool NotifticationRequestBox::GetBigIcon(std::shared_ptr<Media::PixelMap>& bigIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::string bigIconContent;
    if (!box_->GetStringValue(NOTIFICATION_BIG_ICON, bigIconContent)) {
        return false;
    }
    ANS_LOGI("GetBigIcon %{public}s", bigIconContent.c_str());
    bigIcon = AnsImageUtil::UnPackImage(bigIconContent);
    return true;
}

bool NotifticationRequestBox::GetOverlayIcon(std::shared_ptr<Media::PixelMap>& overlayIcon) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::string overlayContent;
    if (!box_->GetStringValue(NOTIFICATION_OVERLAY_ICON, overlayContent)) {
        return false;
    }
    ANS_LOGI("GetOverlayIcon %{public}s", overlayContent.c_str());
    overlayIcon = AnsImageUtil::UnPackImage(overlayContent);
    return true;
}

bool NotifticationRequestBox::GetCommonLiveView(std::vector<uint8_t>& byteSequence) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetBytes(NOTIFICATION_COMMON_LIVEVIEW, byteSequence);
}
}
}
