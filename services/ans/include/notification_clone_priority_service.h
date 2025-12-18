/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_H

#include "notification_clone_template.h"

#include "ffrt.h"
#include "notification_clone_priority_info.h"

namespace OHOS {
namespace Notification {
class NotificationClonePriority final : public NotificationCloneTemplate {
public:
    static std::shared_ptr<NotificationClonePriority> GetInstance();
    ErrCode OnBackup(nlohmann::json &jsonObject) override;
    void OnRestoreEnd(int32_t userId) override;
    void OnRestoreStart(const std::string bundleName, int32_t appIndex, int32_t userId, int32_t uid) override;
    void OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps) override;
    void OnUserSwitch(int32_t userId) override;

private:
    void RestoreBundlePriorityInfo(const int32_t uid, const NotificationClonePriorityInfo &priorityInfo);
    void SetDefaultPriorityInfo(const int32_t uid, const std::string &bundleName);
    void BatchSetDefaultPriorityInfo(const std::set<std::string> &bundleNames);
private:
    std::vector<NotificationClonePriorityInfo> priorityInfo_;
    ffrt::mutex lock_;
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_PRIORITY_H
