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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_DISTURB_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_DISTURB_H

#include "notification_clone_template.h"

#include "ffrt.h"
#include "notification_bundle_option.h"
#include "notification_do_not_disturb_profile.h"

namespace OHOS {
namespace Notification {
class NotificationCloneDisturb final : public NotificationCloneTemplate {
public:
    NotificationCloneDisturb();
    ~NotificationCloneDisturb() override;
    static std::shared_ptr<NotificationCloneDisturb> GetInstance();
    ErrCode OnBackup(nlohmann::json &jsonObject) override;
    void OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps) override;
    void OnRestoreStart(const std::string bundleName, int32_t appIndex, int32_t userId, int32_t uid) override;
    int32_t GetBundleUid(const std::string bundleName, int32_t userId, int32_t appIndex);
    void GetProfileUid(int32_t userId, const std::set<std::string>& systemApps,
        std::vector<NotificationBundleOption> trustList, std::vector<NotificationBundleOption>& exitBunldleList,
        std::vector<NotificationBundleOption>& notExitBunldleList);
    void CheckBundleInfo(std::vector<NotificationBundleOption>& trustList,
        std::vector<NotificationBundleOption>& bundleList, const NotificationBundleOption& bundle);
    int32_t GetActiveUserId();
    void OnUserSwitch(int32_t userId) override;

private:
    std::atomic<int32_t> userId_ = -1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles_;
    std::shared_ptr<ffrt::queue> cloneDisturbQueue_ = nullptr;
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_DISTURB_H
