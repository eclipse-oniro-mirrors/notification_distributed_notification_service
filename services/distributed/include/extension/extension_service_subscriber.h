/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBER_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBER_H

#include "ffrt.h"
#include "extension_service_common.h"
#include "notification_bundle_option.h"
#include "notification_subscriber.h"

namespace OHOS {
namespace Notification {
class ExtensionServiceSubscriber : public NotificationSubscriber {
public:
    ExtensionServiceSubscriber(const NotificationBundleOption& bundle);
    ~ExtensionServiceSubscriber() override;
    void OnDied() override;
    void OnConnected() override;
    void OnDisconnected() override;
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override;
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override;
    void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override;
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;
    void OnApplicationInfoNeedChanged(const std::string& bundleName) override;
    ErrCode OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo) override;

private:
    std::shared_ptr<ExtensionSubscriberInfo> extensionSubscriberInfo_;
    std::shared_ptr<ffrt::queue> messageQueue_ = nullptr;
};
}
}

#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBER_H
