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

#include "distributed_preferences_info.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
DistributedPreferencesInfo::DistributedPreferencesInfo()
{}

DistributedPreferencesInfo::~DistributedPreferencesInfo()
{}

void DistributedPreferencesInfo::SetDistributedEnable(bool enable)
{
    distributedEnable_ = enable;
}

bool DistributedPreferencesInfo::GetDistributedEnable()
{
    return distributedEnable_;
}

void DistributedPreferencesInfo::SetDistributedBundleEnable(const std::string &bundleName, int32_t uid, bool enable)
{
    bundleEnable_[std::make_pair(bundleName, uid)] = enable;
}

bool DistributedPreferencesInfo::GetDistributedBundleEnable(const std::string &bundleName, int32_t uid)
{
    auto iter = bundleEnable_.find(std::make_pair(bundleName, uid));
    if (iter == bundleEnable_.end()) {
        ANS_LOGW("bundle %{public}s(%{public}d) not found.", bundleName.c_str(), uid);
        return true;
    }

    return iter->second;
}

void DistributedPreferencesInfo::DeleteDistributedBundleInfo(const std::string &bundleName, int32_t uid)
{
    bundleEnable_.erase(std::make_pair(bundleName, uid));
}

void DistributedPreferencesInfo::SetSyncEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    enabledWithoutApp_[userId] = enabled;
}

ErrCode DistributedPreferencesInfo::GetSyncEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    auto iter = enabledWithoutApp_.find(userId);
    if (iter == enabledWithoutApp_.end()) {
        enabled = false;
        ANS_LOGW("userId(%{public}d) not found. enabled default false", userId);
    } else {
        enabled = iter->second;
        ANS_LOGI("userId(%{public}d) enabled = %{public}d", userId, enabled);
    }
    return ERR_OK;
}

ErrCode DistributedPreferencesInfo::AddCollaborativeNotification(const std::string &notificationKey)
{
    collaborativeNotificationList_.insert(notificationKey);
    return ERR_OK;
}

bool DistributedPreferencesInfo::CheckCollaborativeNotification(const std::string &notificationKey)
{
    auto it = collaborativeNotificationList_.find(notificationKey);
    if (it != collaborativeNotificationList_.end()) {
        collaborativeNotificationList_.erase(it);
        return true;
    }
    ANS_LOGE("CheckCollaborativeNotification failed");
    return false;
}
}  // namespace Notification
}  // namespace OHOS