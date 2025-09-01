/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <thread>

#define private public
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_ans_subscriber.h"
#include "ans_const_define.h"
#include "notification_preferences.h"

#include "ans_inner_errors.h"
#include "ans_subscriber_listener.h"
#include "mock_i_remote_object.h"

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class MockAnsSubscriberTest : public MockAnsSubscriber  {
public:
    explicit MockAnsSubscriberTest(const sptr<IRemoteObject>& remote) : MockAnsSubscriber(remote) {};
    ErrCode OnConsumed(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override
    {
        isCalled_ = true;
        return ERR_OK;
    }

    ErrCode OnConsumed(const sptr<Notification> &notification) override
    {
        isCalled_ = true;
        return ERR_OK;
    };

    ErrCode OnConsumedWithMaxCapacity(
        const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override
    {
        isCalled_ = true;
        return ERR_OK;
    };

    ErrCode OnConsumedWithMaxCapacity(const sptr<Notification> &notification) override
    {
        isCalled_ = true;
        return ERR_OK;
    };

    bool IsCalled()
    {
        return isCalled_;
    }

private:
    bool isCalled_{false};
};

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
        {
            isCallback_ = true;
        }
        void OnCanceled(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
        {
            isCallback_ = true;
        }
        void OnConsumed(const std::shared_ptr<Notification> &request,
            const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {
            isCallback_ = true;
        }
        void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
        {
            isCallback_ = true;
        }
        void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
        {
            isCallback_ = true;
        }
        void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
        {
            isCallback_ = true;
        }
        void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
        {
            isCallback_ = true;
        }
        void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
            const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
        {
            isCallback_ = true;
        }
        void OnApplicationInfoNeedChanged(const std::string& bundleName) override
        {
            isCallback_ = true;
        }

        ErrCode OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo)
        {
            isCallback_ = true;
            return ERR_OK;
        }

        bool GetCallBack()
        {
            return isCallback_;
        }

        void SetCallBack(bool isCallback)
        {
            isCallback_ = isCallback;
        }
    
    private:
        bool isCallback_;
    };

    static std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager_;
    static TestAnsSubscriber testAnsSubscriber_;
    static sptr<IAnsSubscriber> subscriber_;
};

std::shared_ptr<NotificationSubscriberManager> NotificationSubscriberManagerTest::notificationSubscriberManager_ =
    nullptr;
sptr<IAnsSubscriber> NotificationSubscriberManagerTest::subscriber_ = nullptr;

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
    MockGetOsAccountLocalIdFromUid(true, 0);
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
    std::string bundle = "com.example.test";
    notificationSubscriberManager_->NotifyDoNotDisturbDateChanged(0, date, bundle);

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
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber(new MockIRemoteObject());
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(1);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    sptr<Notification> notification = new Notification(request);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    notifications.emplace_back(nullptr);
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
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber(new MockIRemoteObject());
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
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber(new MockIRemoteObject());
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
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    sptr<Notification> notification(new Notification(request));
    notifications.emplace_back(notification);
     
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    auto record = notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);

    testAnsSubscriber->SetCallBack(false);
    notificationSubscriberManager.notificationSubQueue_ = nullptr;
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}
 
/**
 * @tc.number    : AddSubscriber001
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_001, Function | SmallTest | Level1)
{
    MockGetOsAccountLocalIdFromUid(false, 0);
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    
    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(
        subscriber, nullptr), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddSubscriber_002
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .he
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddDeviceType("current");
    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    info->SetSlotTypes(slotTypes);

    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(subscriber, info), (int)ERR_OK);
    
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    notificationSubscriberManager.NotifyUpdated(notificationMap);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);

    ASSERT_EQ(notificationSubscriberManager.RemoveSubscriber(subscriber, nullptr), (int)ERR_OK);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(102);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_FALSE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_TRUE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSlotTypes(slotTypes);
    subscribeInfo->SetSubscriberUid(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_FALSE(res);
}

// /**
//  * @tc.number    : NotifyConsumed_001
//  * @tc.name      :
//  */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumed_001, Function | SmallTest | Level1)
{
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::OTHER);
    request->SetLabel("label");
    request->SetCreatorUid(0);
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    EXPECT_NE(pictureContent, nullptr);
    pictureContent->SetText("notification text");
    pictureContent->SetTitle("notification title");
    pictureContent->SetBigPicture(nullptr);
    EXPECT_EQ(nullptr, pictureContent->GetBigPicture());
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    request->SetContent(content);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    notificationSubscriberManager.NotifyConsumed(notification, notificationMap);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyBadgeEnabledChanged_001
 * @tc.name      : test notify badge enable to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyBadgeEnabledChanged_001, Function | SmallTest | Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    std::string bundle = "com.example.test";
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber, subscribeInfo), (int)ERR_OK);
    sptr<EnabledNotificationCallbackData> callbackData(new EnabledNotificationCallbackData());
    callbackData->SetBundle(bundle);
    notificationSubscriberManager_->NotifyBadgeEnabledChanged(callbackData);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : ConsumeRecordFilter_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationActionButton> actionButton =
        std::make_shared<NotificationActionButton>();
    std::shared_ptr<NotificationUserInput> userInput = NotificationUserInput::Create("userInput");
    actionButton->AddNotificationUserInput(userInput);

    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->AddActionButton(actionButton);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(2);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_FALSE(res);
}

/**
 * @tc.number    : ConsumeRecordFilter_002
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationActionButton> actionButton = std::make_shared<NotificationActionButton>();
    std::shared_ptr<NotificationUserInput> userInput = NotificationUserInput::Create("userInput");
    actionButton->AddNotificationUserInput(userInput);

    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->AddActionButton(actionButton);
    sptr<Notification> notification(new Notification(request));

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(4);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_TRUE(res);
}

/**
 * @tc.number    : ConsumeRecordFilter_003
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<Notification> notification(new Notification(request));

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetFilterType(1);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.ConsumeRecordFilter(record, notification);
    ASSERT_FALSE(res);
}

/**
 * @tc.number    : BatchNotifyCanceledInner_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyCanceledInner_001, Function | SmallTest | Level1)
{
    //build request
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetLabel("label");
    request->SetCreatorUid(0);
    std::shared_ptr<NotificationLiveViewContent> liveViewContentcontent =
        std::make_shared<NotificationLiveViewContent>();
    liveViewContentcontent->SetText("notification text");
    liveViewContentcontent->SetTitle("notification title");
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pixelMap;
    liveViewContentcontent->SetPicture(pixelMap);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContentcontent);
    request->SetContent(content);
    sptr<Notification> notification(new Notification(request));

    sptr<NotificationRequest> requestLocal(new NotificationRequest());
    requestLocal->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    requestLocal->SetLabel("label");
    requestLocal->SetCreatorUid(0);
    std::shared_ptr<NotificationLocalLiveViewContent> liveViewLocalContentcontent =
        std::make_shared<NotificationLocalLiveViewContent>();
    liveViewLocalContentcontent->SetText("notification text");
    liveViewLocalContentcontent->SetTitle("notification title");
    std::shared_ptr<NotificationContent> contentLocal =
        std::make_shared<NotificationContent>(liveViewLocalContentcontent);
    requestLocal->SetContent(contentLocal);
    sptr<Notification> notificationLocal(new Notification(requestLocal));

    std::vector<sptr<Notification>> notifications;
    notifications.push_back(notification);
    notifications.push_back(notificationLocal);
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    //brach need nullptr
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);

    notificationSubscriberManager.BatchNotifyCanceledInner(notifications, notificationMap, 99);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyDoNotDisturbDateChangedInner_001
 * @tc.name      : test set do not disturb date to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyDoNotDisturbDateChangedInner_001, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<NotificationDoNotDisturbDate> date(new NotificationDoNotDisturbDate());
    std::string bundle = "com.example.test";

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    
    info->AddAppUserId(101);
    info->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyDoNotDisturbDateChangedInner(101, date, bundle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledNotificationChangedInner_002
 * @tc.name      : test enable notification changed to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledNotificationChangedInner_002, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<EnabledNotificationCallbackData> callback(new EnabledNotificationCallbackData());
    std::string bundle = "com.example.test";
    callback->SetBundle(bundle);
    callback->SetUid(101);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledNotificationChangedInner(callback);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : SetBadgeNumber_001
 * @tc.name      : test set badge number to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, SetBadgeNumber_001, Function | SmallTest | Level1)
{
    //build notificationMap
    sptr<BadgeNumberCallbackData> badge(new BadgeNumberCallbackData());
    std::string bundle = "com.example.test";
    badge->SetBundle(bundle);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.SetBadgeNumber(badge);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyApplicationInfoNeedChanged_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyApplicationInfoNeedChanged_001, Function | SmallTest | Level1)
{
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyApplication(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyApplicationInfoNeedChanged("test");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : DistributeOperation_001
 * @tc.name      : test DistributeOperation call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_001, Function | SmallTest | Level1)
{
    sptr<NotificationOperationInfo> operationInfo(new NotificationOperationInfo);
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyResponse(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr request = new (std::nothrow) NotificationRequest();
    notificationSubscriberManager.DistributeOperation(operationInfo, request);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : DistributeOperation_002
 * @tc.name      : test DistributeOperation with operationInfo nullptr
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    ASSERT_EQ((int)ERR_ANS_TASK_ERR, notificationSubscriberManager.DistributeOperation(nullptr, nullptr));
}

/**
 * @tc.number    : DistributeOperation_003
 * @tc.name      : test DistributeOperation ERR_ANS_DISTRIBUTED_OPERATION_FAILED
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    request->SetExtendInfo(extendInfo);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("hashCode");
    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);
    notificationSubscriberManager.subscriberRecordList_.push_back(
        notificationSubscriberManager.CreateSubscriberRecord(nullptr));
    ASSERT_EQ((int)ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
        notificationSubscriberManager.DistributeOperation(operationInfo, request));
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

HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_recordNotNull, TestSize.Level1)
{
    // Arrange
    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.notificationSubQueue_ = std::make_shared<ffrt::queue>("test");
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberUid = 123;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);
    LivePublishProcess::GetInstance()->AddLiveViewSubscriber(123);

    notificationSubscriberManager.OnRemoteDied(subscriber->AsObject());

    EXPECT_EQ(notificationSubscriberManager.subscriberRecordList_.size(), 0);
    EXPECT_TRUE(LivePublishProcess::GetInstance()->GetLiveViewSubscribeState(123));
}

HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_recordIsSubscribeSelf, TestSize.Level1)
{
    // Arrange
    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.notificationSubQueue_ = std::make_shared<ffrt::queue>("test");
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberUid = 123;
    record->isSubscribeSelf = true;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);
    LivePublishProcess::GetInstance()->AddLiveViewSubscriber(123);

    notificationSubscriberManager.OnRemoteDied(subscriber->AsObject());

    EXPECT_EQ(notificationSubscriberManager.subscriberRecordList_.size(), 0);
    EXPECT_FALSE(LivePublishProcess::GetInstance()->GetLiveViewSubscribeState(123));
}

/**
 * @tc.name: NotifyConsumedInner_001
 * @tc.desc: Test NotifyConsumedInner when notification is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_001, Function | SmallTest | Level1)
{
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;

    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    ASSERT_EQ(notification, nullptr);
}

/**
 * @tc.name: NotifyConsumedInner_002
 * @tc.desc: Test NotifyConsumedInner when notificationMap is not nullptr and notification type is not liveview
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    auto isCall = subscriber->IsCalled();
    ASSERT_TRUE(isCall);
}

/**
 * @tc.name: NotifyConsumedInner_003
 * @tc.desc: Test NotifyConsumedInner when notificationMap is not nullptr and notification type is liveview
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_003, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    auto isCall = subscriber->IsCalled();
    ASSERT_TRUE(isCall);
}

/**
 * @tc.name: NotifyConsumedInner_004
 * @tc.desc: Test NotifyConsumedInner when notificationMap is nullptr and notification type is not liveview
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_004, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = nullptr;

    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    auto isCall = subscriber->IsCalled();
    ASSERT_TRUE(isCall);
}

/**
 * @tc.name: NotifyConsumedInner_005
 * @tc.desc: Test NotifyConsumedInner when notificationMap is nullptr and notification type is liveview
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_005, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = nullptr;

    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    auto isCall = subscriber->IsCalled();
    ASSERT_TRUE(isCall);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/**
 * @tc.name: GetIsEnableEffectedRemind_001
 * @tc.desc: Test GetIsEnableEffectedRemind when subscriberRecordList_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, GetIsEnableEffectedRemind_001, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;

    auto ret = notificationSubscriberManager.GetIsEnableEffectedRemind();

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetIsEnableEffectedRemind_002
 * @tc.desc: Test GetIsEnableEffectedRemind when subscriberRecordList_ is not empty
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, GetIsEnableEffectedRemind_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->AddDeviceType(NotificationConstant::PC_DEVICE_TYPE);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    auto ret = notificationSubscriberManager.GetIsEnableEffectedRemind();

    ASSERT_TRUE(ret);
}
/**
 * @tc.name: IsDeviceTypeSubscriberd_001
 * @tc.desc: Test IsDeviceTypeSubscriberd when subscriberRecordList_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeSubscriberd_001, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::string deviceType = NotificationConstant::PC_DEVICE_TYPE;

    auto ret = notificationSubscriberManager.IsDeviceTypeSubscriberd(deviceType);

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: IsDeviceTypeSubscriberd_002
 * @tc.desc: Test IsDeviceTypeSubscriberd when subscriberRecordList_ is not empty
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeSubscriberd_002, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::string deviceType = NotificationConstant::PC_DEVICE_TYPE;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->AddDeviceType(deviceType);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    auto ret = notificationSubscriberManager.IsDeviceTypeSubscriberd(deviceType);

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: IsDeviceTypeAffordConsume_001
 * @tc.desc: Test IsDeviceTypeAffordConsume
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeAffordConsume_001, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::string deviceType = NotificationConstant::PC_DEVICE_TYPE;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->AddDeviceType(deviceType);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    bool result = false;

    notificationSubscriberManager.IsDeviceTypeAffordConsume(deviceType, request, result);

    ASSERT_TRUE(result);
}
#endif
}  // namespace Notification
}  // namespace OHOS
