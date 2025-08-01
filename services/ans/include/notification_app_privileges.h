/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
 

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_APP_PRIVILEGES_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_APP_PRIVILEGES_H

#include <string>

namespace OHOS {
namespace Notification {
class NotificationAppPrivileges {
public:
    NotificationAppPrivileges(const std::string &flagStr);
    ~NotificationAppPrivileges() = default;
    
    bool IsLiveViewEnabled() const;
    bool IsBannerEnabled() const;
    bool IsReminderEnabled() const;
    bool IsDistributedReplyEnabled() const;

private:
    static constexpr int32_t DISTRIBUTED_REPLY_SEQ = 4;
    static constexpr int32_t REMINDER_ENABLED_SEQ = 2;
    static constexpr int32_t BANNER_ENABLED_SEQ = 1;
    static constexpr int32_t LIVE_VIEW_ENABLED_SEQ = 0;

    static constexpr char DISTRIBUTED_REPLY_ENABLE = '1';
    static constexpr char REMINDER_ENABLE = '1';
    static constexpr char BANNER_ENABLE = '1';
    static constexpr char LIVE_VIEW_ENABLE = '1';

    uint32_t privileges_ = 0;
};
} // namespace Notification
} // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_APP_PRIVILEGES_H
