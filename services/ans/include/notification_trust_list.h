/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_TRUST_LIST_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_TRUST_LIST_H

#include <cstdint>
#include <singleton.h>
#include <string>
#include <set>

#include "nlohmann/json.hpp"
#include "notification_config_parse.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {
class NotificationTrustList : public DelayedSingleton<NotificationTrustList> {
public:
    NotificationTrustList();
    ~NotificationTrustList();

    void GetCcmPrivilegesConfig();

    bool IsLiveViewTrtust(const std::string bundleName);
    bool IsSlotFlagsTrustlistAsBundle(const sptr<NotificationBundleOption> &bundleOption);
    bool IsReminderTrustList(const std::string& bundleName);
private:
    std::set<std::string> liveViewTrustlist_;
    std::set<std::string> reminderTrustlist_;
    std::set<std::string> notificationSlotFlagsTrustlist_;
    constexpr static inline const uint32_t PRIVILEGES_CONFIG_MIN_LEN = 2;
    constexpr static inline const uint32_t PRIVILEGES_BANNER_INDEX = 1;
    constexpr static inline const char PRIVILEGES_BANNER_NOT_ALLOW = '0';
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_TRUST_LIST_H
