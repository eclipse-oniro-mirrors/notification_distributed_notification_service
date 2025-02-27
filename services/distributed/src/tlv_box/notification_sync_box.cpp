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

#include "notification_sync_box.h"

#include <sstream>
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

NotificationSyncBox::NotificationSyncBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(SYNC_NOTIFICATION);
}

NotificationSyncBox::~NotificationSyncBox()
{}

NotificationSyncBox::NotificationSyncBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotificationSyncBox::SetLocalDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool NotificationSyncBox::SetNotificationList(const std::vector<std::string>& notificationList)
{
    if (box_ == nullptr) {
        return false;
    }
    std::ostringstream listStream;
    for (auto& notification : notificationList) {
        listStream << notification << ' ';
    }
    std::string result = listStream.str();
    ANS_LOGI("SetNotificationList %{public}s", result.c_str());
    return box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_HASHCODE, result));
}

bool NotificationSyncBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool NotificationSyncBox::GetNotificationList(std::unordered_set<std::string>& notificationList) const
{
    if (box_ == nullptr) {
        return false;
    }
    std::string notificationContent;
    if (!box_->GetStringValue(NOTIFICATION_HASHCODE, notificationContent)) {
        return false;
    }

    ANS_LOGI("SetNotificationList %{public}s", notificationContent.c_str());
    std::istringstream listStream(notificationContent);
    std::string hashCode;
    while (listStream >> hashCode) {
        if (!hashCode.empty()) {
            notificationList.insert(hashCode);
        }
    }
    return true;
}

}
}
