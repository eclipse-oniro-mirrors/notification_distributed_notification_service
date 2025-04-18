/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "notification_app_privileges.h"

namespace OHOS {
namespace Notification {
NotificationAppPrivileges::NotificationAppPrivileges(const std::string &flagStr)
{
    if (flagStr.size() > LIVE_VIEW_ENABLED_SEQ && flagStr[LIVE_VIEW_ENABLED_SEQ] == '1') {
        privileges_ |= 1 << LIVE_VIEW_ENABLED_SEQ;
    }
    if (flagStr.size() > BANNER_ENABLED_SEQ && flagStr[BANNER_ENABLED_SEQ] == '1') {
        privileges_ |= 1 << BANNER_ENABLED_SEQ;
    }
    if (flagStr.size() > REMINDER_ENABLED_SEQ && flagStr[REMINDER_ENABLED_SEQ] == '1') {
        privileges_ |= 1 << REMINDER_ENABLED_SEQ;
    }
}
bool NotificationAppPrivileges::IsLiveViewEnabled() const
{
    if ((privileges_ & (1 << LIVE_VIEW_ENABLED_SEQ)) != 0) {
        return true;
    }
    return false;
}
bool NotificationAppPrivileges::IsBannerEnabled() const
{
    if ((privileges_ & (1 << BANNER_ENABLED_SEQ)) != 0) {
        return true;
    }
    return false;
}
bool NotificationAppPrivileges::IsReminderEnabled() const
{
    if ((privileges_ & (1 << REMINDER_ENABLED_SEQ)) != 0) {
        return true;
    }
    return false;
}
} // namespace Notification
} // namespace OHOS