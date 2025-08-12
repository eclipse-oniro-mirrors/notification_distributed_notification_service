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

#include "distributed_collaboration_service.h"

#include "advanced_notification_inline.h"

namespace OHOS {
namespace Notification {

static const int64_t DEFAULT_CONFLICT_TIME = 5 * 1000; // 5s

DistributedCollaborationService& DistributedCollaborationService::GetInstance()
{
    static DistributedCollaborationService distributedCollaborationService;
    return distributedCollaborationService;
}

void DistributedCollaborationService::AddCollaborativeDeleteItem(const sptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        return;
    }
    auto request = notification->GetNotificationRequestPoint();
    if (!request->GetDistributedCollaborate() || !request->IsCommonLiveView()) {
        return;
    }
    std::string hashCode = notification->GetKey();
    std::lock_guard<ffrt::mutex> lock(mapLock);
    collaborativeDeleteMap_[hashCode] = GetCurrentTime();
    ANS_LOGI("Collaborate add %{public}s", hashCode.c_str());
}

bool DistributedCollaborationService::CheckCollaborativePublish(const sptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        return true;
    }
    auto request = notification->GetNotificationRequestPoint();
    if (!request->GetDistributedCollaborate() || !request->IsCommonLiveView()) {
        return true;
    }

    auto content = request->GetContent();
    if (content == nullptr || content->GetNotificationContent() == nullptr) {
        return true;
    }
    std::string hashCode = notification->GetKey();
    auto liveView = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    if (liveView->GetLiveViewStatus() == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE) {
        std::lock_guard<ffrt::mutex> lock(mapLock);
        collaborativeDeleteMap_.erase(hashCode);
        return true;
    }

    int64_t currentTime = GetCurrentTime();
    std::lock_guard<ffrt::mutex> lock(mapLock);
    for (auto item = collaborativeDeleteMap_.begin(); item != collaborativeDeleteMap_.end();) {
        if (currentTime < item->second || currentTime - item->second >= DEFAULT_CONFLICT_TIME) {
            collaborativeDeleteMap_.erase(item++);
        } else {
            item++;
        }
    }
    if (collaborativeDeleteMap_.find(hashCode) != collaborativeDeleteMap_.end()) {
        ANS_LOGW("Collaborate conflict %{public}s", hashCode.c_str());
        return false;
    }
    return true;
}

}
}
