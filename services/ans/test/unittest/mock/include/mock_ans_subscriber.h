/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "ans_subscriber_interface.h"

namespace OHOS {
namespace Notification {
class MockAnsSubscriber : public AnsSubscriberInterface {
public:
    MockAnsSubscriber() {}
    ~MockAnsSubscriber() {}

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
    void OnConnected() override {};

    void OnDisconnected() override {};

    void OnConsumed(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) override {};

    MOCK_METHOD(void, OnConsumedList, (const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap));

    void OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) override {};

    void OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override {};

    void OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override {};

    void OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override {};

    void OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {};

    void OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override {};

    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {};

    void OnApplicationInfoNeedChanged(const std::string& bundleName) override {};
};
} // namespace Notification
} // namespace OHOS
#endif
