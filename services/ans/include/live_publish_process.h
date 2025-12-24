/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LIVE_PUBLISH_PROCESS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LIVE_PUBLISH_PROCESS_H

#include "base_publish_process.h"
#include "ans_status.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
class LivePublishProcess final : public BasePublishProcess {
public:
    static std::shared_ptr<LivePublishProcess> GetInstance();
    AnsStatus PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed) override;
    AnsStatus PublishNotificationByApp(const sptr<NotificationRequest> &request) override;
    void EraseLiveViewSubsciber(int32_t uid);
    void AddLiveViewSubscriber(int32_t uid);
    bool CheckLocalLiveViewSubscribed(
        const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed, int32_t uid);

private:
    bool CheckLocalLiveViewAllowed(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed);
    bool GetLiveViewSubscribeState(int32_t uid);

    std::set<int32_t> localLiveViewSubscribedList_;
    ffrt::mutex liveViewMutext_;
    static std::shared_ptr<LivePublishProcess> instance_;
    static ffrt::mutex instanceMutex_;
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LIVE_PUBLISH_PROCESS_H
