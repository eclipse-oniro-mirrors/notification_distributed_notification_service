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

#include "ans_notification.h"

namespace OHOS {
namespace Notification {
void AnsNotification::AddSubscriptionRecord(const sptr<IAnsSubscriber> &stub,
    const sptr<NotificationSubscribeInfo> &subscribeInfo, bool isSelf, bool isV26, uint32_t subscribedFlags)
{
    if (stub == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    for (auto &item : subscriptionRecords_) {
        if (item.first.promote() == stub) {
            item.second.subscribeInfo = subscribeInfo;
            item.second.isSelf = isSelf;
            item.second.isV26 = isV26;
            item.second.subscribedFlags = subscribedFlags;
            return;
        }
    }
    SubscriptionRecord record;
    record.subscribeInfo = subscribeInfo;
    record.isSelf = isSelf;
    record.isV26 = isV26;
    record.subscribedFlags = subscribedFlags;
    subscriptionRecords_.emplace_back(stub, record);
}

void AnsNotification::RemoveSubscriptionRecord(const sptr<IAnsSubscriber> &stub)
{
    if (stub == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    RemoveSubscriptionRecordLocked(stub);
}

void AnsNotification::RemoveSubscriptionRecordLocked(const sptr<IAnsSubscriber> &stub)
{
    // caller must hold subscriberMutex_
    for (auto it = subscriptionRecords_.begin(); it != subscriptionRecords_.end(); ++it) {
        if (it->first.promote() == stub) {
            subscriptionRecords_.erase(it);
            return;
        }
    }
}

void AnsNotification::ReSubscribeNotifications()
{
    std::vector<std::pair<sptr<IAnsSubscriber>, SubscriptionRecord>> liveRecords;
    {
        std::lock_guard<std::mutex> lock(subscriberMutex_);
        for (auto it = subscriptionRecords_.begin(); it != subscriptionRecords_.end();) {
            sptr<IAnsSubscriber> stub = it->first.promote();
            if (stub == nullptr) {
                it = subscriptionRecords_.erase(it);
                continue;
            }
            liveRecords.emplace_back(stub, it->second);
            ++it;
        }
    }

    for (const auto &item : liveRecords) {
        sptr<IAnsManager> proxy = GetAnsManagerProxy();
        if (!proxy) {
            continue;
        }
        const sptr<IAnsSubscriber> &stub = item.first;
        const SubscriptionRecord &record = item.second;
        if (record.isV26) {
            if (record.subscribeInfo == nullptr) {
                proxy->SubscribeNotification(stub, record.subscribedFlags);
            } else {
                proxy->SubscribeNotification(stub, record.subscribeInfo, record.subscribedFlags);
            }
        } else if (record.isSelf) {
            proxy->SubscribeSelf(stub, record.subscribedFlags);
        } else {
            if (record.subscribeInfo == nullptr) {
                proxy->Subscribe(stub, record.subscribedFlags);
            } else {
                proxy->Subscribe(stub, record.subscribeInfo, record.subscribedFlags);
            }
        }
    }
}
}  // namespace Notification
}  // namespace OHOS
