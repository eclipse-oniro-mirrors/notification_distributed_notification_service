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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SYNC_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SYNC_BOX_H

#include <unordered_set>
#include <string>
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {
class NotificationSyncBox : public BoxBase {
public:
    NotificationSyncBox();
    ~NotificationSyncBox();
    NotificationSyncBox(std::shared_ptr<TlvBox> box);
#ifdef DISTRIBUTED_FEATURE_MASTER
    bool SetLocalDeviceId(const std::string& deviceId);
    bool SetNotificationEmpty(const bool empty);
    bool SetNotificationList(const std::vector<std::string>& notificationList);
#else
    bool GetLocalDeviceId(std::string& deviceId) const;
    bool GetNotificationEmpty(bool& empty) const;
    bool GetNotificationList(std::unordered_set<std::string>& notificationList) const;
#endif
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SYNC_BOX_H
