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
#include "notification_trust_list.h"

namespace OHOS {
namespace Notification {

constexpr static uint32_t LIVE_VIEW_INDEX = 0;
constexpr static uint32_t REMINDER_LIST_INDEX = 2;
NotificationTrustList::NotificationTrustList()
{
    GetCcmPrivilegesConfig();
}

NotificationTrustList::~NotificationTrustList() = default;

void NotificationTrustList::GetCcmPrivilegesConfig()
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(NotificationConfigParse::APP_PRIVILEGES);
    if (!NotificationConfigParse::GetInstance()->GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("Failed to get JsonPoint CCM config file.");
        return;
    }
    if (!root.contains(NotificationConfigParse::APP_PRIVILEGES)) {
        ANS_LOGW("not found jsonKey appPrivileges");
        return;
    }
    nlohmann::json affects = root[NotificationConfigParse::APP_PRIVILEGES];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetCcmPrivileges failed as invalid ccmPrivileges json.");
        return;
    }
    for (auto &affect : affects.items()) {
        std::string affects_value = affect.value().get<std::string>();
        if (affects_value[LIVE_VIEW_INDEX] != PRIVILEGES_BANNER_NOT_ALLOW) {
            liveViewTrustlist_.insert(affect.key());
        }
        if (affects_value.length() >= PRIVILEGES_CONFIG_MIN_LEN &&
            affects_value[PRIVILEGES_BANNER_INDEX] != PRIVILEGES_BANNER_NOT_ALLOW) {
            notificationSlotFlagsTrustlist_.insert(affect.key());
        }
        if (affects_value.length() >= REMINDER_LIST_INDEX + 1 &&
            affects_value[REMINDER_LIST_INDEX] != PRIVILEGES_BANNER_NOT_ALLOW) {
            reminderTrustlist_.insert(affect.key());
        }
    }
    return;
}

bool NotificationTrustList::IsLiveViewTrtust(const std::string bundleName)
{
    return liveViewTrustlist_.count(bundleName);
}

bool NotificationTrustList::IsReminderTrustList(const std::string& bundleName)
{
    return reminderTrustlist_.count(bundleName);
}

bool NotificationTrustList::IsSlotFlagsTrustlistAsBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    return notificationSlotFlagsTrustlist_.count(bundleOption->GetBundleName());
}
} // namespace Notification
} // namespace OHOS
