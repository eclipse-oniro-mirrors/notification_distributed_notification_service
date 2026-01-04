/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <functional>
#include "gtest/gtest.h"
#define private public
#include "ans_subscriber_listener.h"
#undef private
 
using namespace testing::ext;
namespace OHOS {
namespace Notification {
class SubscriberListenerTest : public ::testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    void SetUp(){};
    void TearDown(){};
};
 
class TestSubscriber : public NotificationSubscriber {
public:
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
 
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
 
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    bool NotificationSubscriber::ProcessSyncDecision(
        const std::string &deviceType, std::shared_ptr<Notification> &notification) override
    {
        return notification->GetNotificationRequestPoint() != nullptr;
    }
#endif
 
    bool HasOnBatchCancelCallback() override
    {
        return true;
    }
};
 
class TestNoBatchSubscriber : public NotificationSubscriber {
public:
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnEnabledNotificationChanged(const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
 
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
 
    bool HasOnBatchCancelCallback() override
    {
        return false;
    }
};
 
/**
 * @tc.name      : OnConnected_0100
 * @tc.desc      : Test OnConnected success
 */
HWTEST_F(SubscriberListenerTest, OnConnected_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConnected();
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnConnected_0200
 * @tc.desc      : Test OnConnected invalid data
 */
HWTEST_F(SubscriberListenerTest, OnConnected_0200, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnConnected();
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnDisconnected_0100
 * @tc.desc      : Test OnConnected success
 */
HWTEST_F(SubscriberListenerTest, OnDisconnected_0100, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnDisconnected();
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnDisconnected_0200
 * @tc.desc      : Test OnConnected invalid data
 */
HWTEST_F(SubscriberListenerTest, OnDisconnected_0200, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnDisconnected();
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnConsumed_0100
 * @tc.desc      : Test OnConsumed invalid data
 */
HWTEST_F(SubscriberListenerTest, OnConsumed_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnConsumed(nullptr, nullptr);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/**
 * @tc.name      : OnConsumed_0200
 * @tc.desc      : Test OnConsumed invalid operation
 */
HWTEST_F(SubscriberListenerTest, OnConsumed_0200, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumed(notification, notificationMap);
    EXPECT_EQ(result, ERR_INVALID_OPERATION);
}
#endif
 
/**
 * @tc.name      : OnConsumed_0300
 * @tc.desc      : Test OnConsumed success
 */
HWTEST_F(SubscriberListenerTest, OnConsumed_0300, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumed(notification, notificationMap);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnConsumed_0400
 * @tc.desc      : Test one param OnConsumed success
 */
HWTEST_F(SubscriberListenerTest, OnConsumed_0400, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumed(notification);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnConsumed_0500
 * @tc.desc      : Test one param OnConsumed success
 */
HWTEST_F(SubscriberListenerTest, OnConsumed_0500, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    request->SetClassification(NotificationConstant::ANS_VOIP);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    subscriber->SetDeviceType(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE);
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumed(notification, notificationMap);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnConsumedWithMaxCapacity_0100
 * @tc.desc      : Test OnConsumedWithMaxCapacity success
 */
HWTEST_F(SubscriberListenerTest, OnConsumedWithMaxCapacity_0100, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumedWithMaxCapacity(notification, notificationMap);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnConsumedWithMaxCapacity_0200
 * @tc.desc      : Test one param OnConsumedWithMaxCapacity success
 */
HWTEST_F(SubscriberListenerTest, OnConsumedWithMaxCapacity_0200, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumedWithMaxCapacity(notification);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnConsumedList_0100
 * @tc.desc      : Test OnConsumedList success
 */
HWTEST_F(SubscriberListenerTest, OnConsumedList_0100, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumedList(notifications, notificationMap);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnConsumedList_0200
 * @tc.desc      : Test one param OnConsumedList success
 */
HWTEST_F(SubscriberListenerTest, OnConsumedList_0200, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification("001", request);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnConsumedList(notifications);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceled_0100
 * @tc.desc      : Test OnCanceled invalid data
 */
HWTEST_F(SubscriberListenerTest, OnCanceled_0100, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnCanceled(notification, nullptr, 0);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnCanceled_0200
 * @tc.desc      : Test OnCanceled notificationMap nullptr
 */
HWTEST_F(SubscriberListenerTest, OnCanceled_0200, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceled(notification, nullptr, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceled_0300
 * @tc.desc      : Test OnCanceled notificationMap not nullptr
 */
HWTEST_F(SubscriberListenerTest, OnCanceled_0300, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceled(notification, notificationMap, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceled_0400
 * @tc.desc      : Test two params OnCanceled
 */
HWTEST_F(SubscriberListenerTest, OnCanceled_0400, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceled(notification, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceledWithMaxCapacity_0100
 * @tc.desc      : Test OnCanceledWithMaxCapacity success
 */
HWTEST_F(SubscriberListenerTest, OnCanceledWithMaxCapacity_0100, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceledWithMaxCapacity(notification, notificationMap, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceledWithMaxCapacity_0200
 * @tc.desc      : Test two params OnCanceledWithMaxCapacity
 */
HWTEST_F(SubscriberListenerTest, OnCanceledWithMaxCapacity_0200, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceledWithMaxCapacity(notification, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnBatchCanceled_0100
 * @tc.desc      : Test OnBatchCanceled invalid data
 */
HWTEST_F(SubscriberListenerTest, OnBatchCanceled_0100, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    sptr<SubscriberListener> listener = new (std::nothrow) SubscriberListener(nullptr);
    listener->OnBatchCanceled(notifications, nullptr, 0);
    EXPECT_EQ(notifications.size(), 1);
}
 
/**
 * @tc.name      : OnBatchCanceled_0200
 * @tc.desc      : Test OnBatchCanceled notificationMap nullptr
 */
HWTEST_F(SubscriberListenerTest, OnBatchCanceled_0200, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestNoBatchSubscriber>();
    sptr<SubscriberListener> listener = new (std::nothrow) SubscriberListener(subscriber);
    listener->OnBatchCanceled(notifications, nullptr, 0);
    EXPECT_EQ(notifications.size(), 1);
}
 
/**
 * @tc.name      : OnBatchCanceled_0300
 * @tc.desc      : Test OnBatchCanceled notificationMap not nullptr
 */
HWTEST_F(SubscriberListenerTest, OnBatchCanceled_0300, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestNoBatchSubscriber>();
    sptr<SubscriberListener> listener = new (std::nothrow) SubscriberListener(subscriber);
    listener->OnBatchCanceled(notifications, notificationMap, 0);
    EXPECT_EQ(notifications.size(), 1);
}
 
/**
 * @tc.name      : OnCanceledList_0100
 * @tc.desc      : Test OnCanceledList invalid data
 */
HWTEST_F(SubscriberListenerTest, OnCanceledList_0100, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnCanceledList(notifications, nullptr, 0);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnCanceledList_0200
 * @tc.desc      : Test OnCanceledList called OnBatchCanceled
 */
HWTEST_F(SubscriberListenerTest, OnCanceledList_0200, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceledList(notifications, nullptr, 0);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnCanceledList_0300
 * @tc.desc      : Test OnCanceledList called OnCanceled
 */
HWTEST_F(SubscriberListenerTest, OnCanceledList_0300, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestNoBatchSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceledList(notifications, nullptr, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnCanceledList_0400
 * @tc.desc      : Test two params OnCanceledList
 */
HWTEST_F(SubscriberListenerTest, OnCanceledList_0400, Function | MediumTest | Level1)
{
    sptr<Notification> notification = new (std::nothrow) Notification("001", nullptr);
    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestNoBatchSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnCanceledList(notifications, 0);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnUpdated_0100
 * @tc.desc      : Test OnUpdated invalid data
 */
HWTEST_F(SubscriberListenerTest, OnUpdated_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ErrCode result = listener->OnUpdated(notificationMap);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnUpdated_0200
 * @tc.desc      : Test OnUpdated success
 */
HWTEST_F(SubscriberListenerTest, OnUpdated_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ErrCode result = listener->OnUpdated(notificationMap);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnDoNotDisturbDateChange_0100
 * @tc.desc      : Test OnDoNotDisturbDateChange invalid data
 */
HWTEST_F(SubscriberListenerTest, OnDoNotDisturbDateChange_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<NotificationDoNotDisturbDate> date =
        new (std::nothrow) NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, 0, 1);
    ErrCode result = listener->OnDoNotDisturbDateChange(date);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnDoNotDisturbDateChange_0200
 * @tc.desc      : Test OnDoNotDisturbDateChange success
 */
HWTEST_F(SubscriberListenerTest, OnDoNotDisturbDateChange_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<NotificationDoNotDisturbDate> date =
        new (std::nothrow) NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, 0, 1);
    ErrCode result = listener->OnDoNotDisturbDateChange(date);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnEnabledNotificationChanged_0100
 * @tc.desc      : Test OnEnabledNotificationChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnEnabledNotificationChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnEnabledNotificationChanged(callbackData);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnEnabledNotificationChanged_0200
 * @tc.desc      : Test OnEnabledNotificationChanged success
 */
HWTEST_F(SubscriberListenerTest, OnEnabledNotificationChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnEnabledNotificationChanged(callbackData);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnBadgeChanged_0100
 * @tc.desc      : Test OnBadgeChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnBadgeChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<BadgeNumberCallbackData> callbackData = new (std::nothrow) BadgeNumberCallbackData("", 100, 1);
    ErrCode result = listener->OnBadgeChanged(callbackData);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnBadgeChanged_0200
 * @tc.desc      : Test OnBadgeChanged success
 */
HWTEST_F(SubscriberListenerTest, OnBadgeChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<BadgeNumberCallbackData> callbackData = new (std::nothrow) BadgeNumberCallbackData("", 100, 1);
    ErrCode result = listener->OnBadgeChanged(callbackData);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnBadgeEnabledChanged_0100
 * @tc.desc      : Test OnBadgeEnabledChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnBadgeEnabledChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnBadgeEnabledChanged(callbackData);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnBadgeEnabledChanged_0200
 * @tc.desc      : Test OnBadgeEnabledChanged success
 */
HWTEST_F(SubscriberListenerTest, OnBadgeEnabledChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnBadgeEnabledChanged(callbackData);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnEnabledPriorityChanged_0100
 * @tc.desc      : Test OnEnabledPriorityChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnEnabledPriorityChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnEnabledPriorityChanged(callbackData);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnEnabledPriorityChanged_0200
 * @tc.desc      : Test OnEnabledPriorityChanged success
 */
HWTEST_F(SubscriberListenerTest, OnEnabledPriorityChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<EnabledNotificationCallbackData> callbackData =
        new (std::nothrow) EnabledNotificationCallbackData("", 100, true);
    ErrCode result = listener->OnEnabledPriorityChanged(callbackData);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnEnabledPriorityByBundleChanged_0100
 * @tc.desc      : Test OnEnabledPriorityByBundleChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnEnabledPriorityByBundleChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<EnabledPriorityNotificationByBundleCallbackData> callbackData =
        new (std::nothrow) EnabledPriorityNotificationByBundleCallbackData(
        "", 100, NotificationConstant::PriorityEnableStatus::DISABLE);
    ErrCode result = listener->OnEnabledPriorityByBundleChanged(callbackData);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnEnabledPriorityByBundleChanged_0200
 * @tc.desc      : Test OnEnabledPriorityByBundleChanged success
 */
HWTEST_F(SubscriberListenerTest, OnEnabledPriorityByBundleChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<EnabledPriorityNotificationByBundleCallbackData> callbackData =
        new (std::nothrow) EnabledPriorityNotificationByBundleCallbackData(
        "", 100, NotificationConstant::PriorityEnableStatus::DISABLE);
    ErrCode result = listener->OnEnabledPriorityByBundleChanged(callbackData);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnEnabledWatchStatusChanged_0100
 * @tc.desc      : Test OnEnabledWatchStatusChanged with invalid watchStatus
 */
HWTEST_F(SubscriberListenerTest, OnEnabledWatchStatusChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    uint32_t invalidWatchStatus = std::numeric_limits<uint32_t>::max();
    ErrCode result = listener->OnEnabledWatchStatusChanged(invalidWatchStatus);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnEnabledWatchStatusChanged_0200
 * @tc.desc      : Test OnEnabledWatchStatusChanged with valid watchStatus
 */
HWTEST_F(SubscriberListenerTest, OnEnabledWatchStatusChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    uint32_t validWatchStatus = 4;
    ErrCode result = listener->OnEnabledWatchStatusChanged(validWatchStatus);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnSystemUpdate_0100
 * @tc.desc      : Test OnSystemUpdate null subscriber
 */
HWTEST_F(SubscriberListenerTest, OnSystemUpdate_0100, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnSystemUpdate(notification);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnSystemUpdate_0200
 * @tc.desc      : Test OnSystemUpdate success
 */
HWTEST_F(SubscriberListenerTest, OnSystemUpdate_0200, Function | MediumTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnSystemUpdate(notification);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name      : OnSystemUpdate_0300
 * @tc.desc      : Test OnSystemUpdate null notification
 */
HWTEST_F(SubscriberListenerTest, OnSystemUpdate_0300, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnSystemUpdate(nullptr);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name      : OnApplicationInfoNeedChanged_0100
 * @tc.desc      : Test OnApplicationInfoNeedChanged invalid data
 */
HWTEST_F(SubscriberListenerTest, OnApplicationInfoNeedChanged_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    ErrCode result = listener->OnApplicationInfoNeedChanged("");
    EXPECT_EQ(result, ERR_INVALID_DATA);
}
 
/**
 * @tc.name      : OnApplicationInfoNeedChanged_0200
 * @tc.desc      : Test OnApplicationInfoNeedChanged success
 */
HWTEST_F(SubscriberListenerTest, OnApplicationInfoNeedChanged_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    ErrCode result = listener->OnApplicationInfoNeedChanged("");
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnOperationResponse_0100
 * @tc.desc      : Test OnOperationResponse invalid data
 */
HWTEST_F(SubscriberListenerTest, OnOperationResponse_0100, Function | MediumTest | Level1)
{
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(nullptr);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    int32_t funcResult;
    ErrCode result = listener->OnOperationResponse(operationInfo, funcResult);
    EXPECT_EQ(result, ERR_OK);
}
 
/**
 * @tc.name      : OnOperationResponse_0200
 * @tc.desc      : Test OnOperationResponse success
 */
HWTEST_F(SubscriberListenerTest, OnOperationResponse_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<NotificationSubscriber> subscriber = std::make_shared<TestSubscriber>();
    sptr<IAnsSubscriber> listener = new (std::nothrow) SubscriberListener(subscriber);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    int32_t funcResult;
    ErrCode result = listener->OnOperationResponse(operationInfo, funcResult);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS