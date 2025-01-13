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

#include <gtest/gtest.h>
#include <iostream>

#define private public
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_ans_subscriber.h"

#include "ans_inner_errors.h"
#include "ans_subscriber_listener.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class NotificationSubscriberManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    class TestAnsSubscriber : public NotificationSubscriber {
    public:
        void OnConnected() override
        {}
        void OnDisconnected() override
        {}
        void OnDied() override
        {}
        void OnEnabledNotificationChanged(
            const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
        {}
        void OnCanceled(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
        {}
        void OnConsumed(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {}
        void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {}
        void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
        {}
        void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
        {}
        void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
        {}
        void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
        {}
        void OnApplicationInfoNeedChanged(const std::string& bundleName) override
        {}
    };

    static std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager_;
    static TestAnsSubscriber testAnsSubscriber_;
    static sptr<AnsSubscriberInterface> subscriber_;
};

std::shared_ptr<NotificationSubscriberManager> NotificationSubscriberManagerTest::notificationSubscriberManager_ =
    nullptr;
sptr<AnsSubscriberInterface> NotificationSubscriberManagerTest::subscriber_ = nullptr;

void NotificationSubscriberManagerTest::SetUpTestCase()
{
    notificationSubscriberManager_ = NotificationSubscriberManager::GetInstance();
    std::shared_ptr<NotificationSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    subscriber_ = new (std::nothrow) SubscriberListener(testAnsSubscriber);
}

void NotificationSubscriberManagerTest::TearDownTestCase()
{
    subscriber_ = nullptr;
    if (notificationSubscriberManager_ != nullptr) {
        notificationSubscriberManager_->ResetFfrtQueue();
        notificationSubscriberManager_ = nullptr;
    }
}

void NotificationSubscriberManagerTest::SetUp()
{
    notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr);
}

void NotificationSubscriberManagerTest::TearDown()
{
    notificationSubscriberManager_->RemoveSubscriber(subscriber_, nullptr);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_001
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test AddSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_001, Function | SmallTest | Level1)
{
    // Test NotifyUpdated function.
    const std::vector<NotificationSorting> sortingList;
    sptr<NotificationSortingMap> map = new NotificationSortingMap(sortingList);
    notificationSubscriberManager_->NotifyUpdated(map);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("test_bundle");
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, info), (int)ERR_OK);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_002
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test AddSubscriber function when subscriber is nullptr, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_002, Function | SmallTest | Level1)
{
    // Test NotifyDisturbModeChanged function.
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    notificationSubscriberManager_->NotifyDoNotDisturbDateChanged(0, date);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_003
 * @tc.name      : ANS_RemoveSubscriber_0100
 * @tc.desc      : Test RemoveSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_003, Function | SmallTest | Level1)
{
    // Test NotifyConsumed function.
    std::vector<NotificationSorting> sortingList;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap(sortingList);
    notificationSubscriberManager_->NotifyConsumed(notification, notificationMap);

    // Test RemoveSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("test_bundle");
    ASSERT_EQ(notificationSubscriberManager_->RemoveSubscriber(subscriber_, info), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_004
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test RemoveSubscriber function when subscriber is nullptr, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_004, Function | SmallTest | Level1)
{
    // Test NotifyCanceled function.
    std::vector<NotificationSorting> sortingList;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap(sortingList);
    int deleteReason = 0;
    notificationSubscriberManager_->NotifyCanceled(notification, notificationMap, deleteReason);

    // Test RemoveSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(notificationSubscriberManager_->RemoveSubscriber(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RegisterOnSubscriberAddCallbackTest_001
 * @tc.name      : RegisterOnSubscriberAddCallback and callback is not nullptr
 * @tc.desc      : Test RegisterOnSubscriberAddCallback .
 */
void OnSubscriberAddFake(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &recode) {}
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_001, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);

    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : RegisterOnSubscriberAddCallbackTest_002
 * @tc.name      : RegisterOnSubscriberAddCallback and callback is nullptr
 * @tc.desc      : Test RegisterOnSubscriberAddCallback .
 */
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_002, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);

    // if callback exist, re-register a nullptr func will fail.
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(nullptr);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : UnRegisterOnSubscriberAddCallbackTest_001
 * @tc.name      : UnRegisterOnSubscriberAddCallback
 * @tc.desc      : Test UnRegisterOnSubscriberAddCallback .
 */
HWTEST_F(NotificationSubscriberManagerTest, UnRegisterOnSubscriberAddCallbackTest_001, Function | SmallTest | Level1)
{
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(OnSubscriberAddFake, std::placeholders::_1);
    notificationSubscriberManager_->RegisterOnSubscriberAddCallback(callback);
    EXPECT_NE(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);

    notificationSubscriberManager_->UnRegisterOnSubscriberAddCallback();
    ASSERT_EQ(notificationSubscriberManager_->onSubscriberAddCallback_, nullptr);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_001
 * @tc.name      : BatchNotifyConsumedInner
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_001, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(1);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    sptr<Notification> notification = new Notification(request);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppName("test");
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_002
 * @tc.name      : BatchNotifyConsumedInner and params is invalid
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_002, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(0);
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, nullptr, nullptr);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_003
 * @tc.name      : BatchNotifyConsumedInner and subscriber isn't subscribed to this notification
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_003, Function | SmallTest | Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(0);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    sptr<Notification> notification = new Notification(request);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppName("test_1");
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);
}

/**
 * @tc.number    : BatchNotifyConsumed_001
 * @tc.name      : BatchNotifyConsumed and params is nullptr
 * @tc.desc      : Test BatchNotifyConsumed .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumed_001, Function | SmallTest | Level1)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber();
    auto record = notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    notificationSubscriberManager_->BatchNotifyConsumed(notifications, notificationMap, record);
 
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    notifications.emplace_back(notification);
    notificationSubscriberManager_->notificationSubQueue_ = nullptr;
    notificationSubscriberManager_->BatchNotifyConsumed(notifications, notificationMap, record);
    EXPECT_NE(notificationSubscriberManager_, nullptr);
}
 
/**
 * @tc.number    : OnRemoteDied_001
 * @tc.name      : OnRemoteDied and params is nullptr
 * @tc.desc      : Test OnRemoteDied .
 */
HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_001, Function | SmallTest | Level1)
{
    notificationSubscriberManager_->notificationSubQueue_ = nullptr;
    wptr<IRemoteObject> obj = nullptr;
    notificationSubscriberManager_->OnRemoteDied(obj);
    EXPECT_NE(notificationSubscriberManager_, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
