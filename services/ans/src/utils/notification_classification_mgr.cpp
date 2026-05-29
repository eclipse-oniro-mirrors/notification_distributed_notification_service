/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_classification_mgr.h"

namespace OHOS {
namespace Notification {
NotificationClassificationMgr& NotificationClassificationMgr::GetInstance()
{
    static NotificationClassificationMgr instance;
    return instance;
}

void NotificationClassificationMgr::AddOrUpdate(
    const std::string& key, sptr<NotificationClassification> classification)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    map_[key] = std::move(classification);
}

bool NotificationClassificationMgr::Remove(const std::string& key)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.erase(key) > 0;
}

sptr<NotificationClassification> NotificationClassificationMgr::Get(
    const std::string& key) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
        return it->second;
    }
    return nullptr;
}

bool NotificationClassificationMgr::Exists(const std::string& key) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.find(key) != map_.end();
}

size_t NotificationClassificationMgr::Size() const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    return map_.size();
}

void NotificationClassificationMgr::Clear()
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    map_.clear();
}
} // namespace Notification
} // namespace OHOS