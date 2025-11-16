/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_MOCK_ANS_SUBCRIBER_OBJECT_H
#define BASE_NOTIFICATION_MOCK_ANS_SUBCRIBER_OBJECT_H

#include "gmock/gmock.h"
#include "ans_subscriber_proxy.h"
#include "enabled_priority_notification_by_bundle_callback_data.h"

namespace OHOS {
namespace Notification {
class MockAnsSubscriber : public AnsSubscriberProxy  {
public:
    explicit MockAnsSubscriber(const sptr<IRemoteObject>& remote) : AnsSubscriberProxy(remote) {};

    ErrCode OnConnected() override { return ERR_OK; };

    ErrCode OnDisconnected() override { return ERR_OK; };

    ErrCode OnConsumed(
        const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override { return ERR_OK; };

    ErrCode OnConsumed(const sptr<Notification> &notification) override { return ERR_OK; };

    ErrCode OnConsumedWithMaxCapacity(
        const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override { return ERR_OK; };

    ErrCode OnConsumedWithMaxCapacity(const sptr<Notification> &notification) override { return ERR_OK; };

    MOCK_METHOD(ErrCode, OnConsumedList, (const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap));

    MOCK_METHOD(ErrCode, OnConsumedList, (const std::vector<sptr<Notification>> &notifications));

    ErrCode OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnCanceled(const sptr<Notification> &notification, int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnCanceledWithMaxCapacity(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnCanceledWithMaxCapacity(
        const sptr<Notification> &notification, int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnCanceledList(
        const std::vector<sptr<Notification>> &notifications, int32_t deleteReason) override { return ERR_OK; };

    ErrCode OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override { return ERR_OK; };

    ErrCode OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override { return ERR_OK; };

    ErrCode OnEnabledNotificationChanged(
        const sptr<EnabledNotificationCallbackData> &callbackData) override { return ERR_OK; };

    ErrCode OnEnabledPriorityByBundleChanged(
        const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData) override { return ERR_OK; };

    ErrCode OnEnabledPriorityChanged(
        const sptr<EnabledNotificationCallbackData> &callbackData) override { return ERR_OK; };

    ErrCode OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override { return ERR_OK; };

    ErrCode OnBadgeEnabledChanged(
        const sptr<EnabledNotificationCallbackData> &callbackData) override { return ERR_OK; };

    ErrCode OnApplicationInfoNeedChanged(const std::string& bundleName) override { return ERR_OK; };

    ErrCode OnOperationResponse(
        const sptr<NotificationOperationInfo>& operationInfo, int32_t& funcResult) override { return 0; }
};
} // namespace Notification
} // namespace OHOS
#endif
