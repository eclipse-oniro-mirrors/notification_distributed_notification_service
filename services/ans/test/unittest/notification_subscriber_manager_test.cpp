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
#include <atomic>
#include <memory>
#include <thread>

#define private public
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_ans_subscriber.h"
#include "ans_const_define.h"
#include "notification_preferences.h"
#include "notification_extension_wrapper.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_subscriber_listener.h"
#include "mock_i_remote_object.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_classification.h"
#include "notification_classification_mgr.h"
#include "notification_switch_changed_callback_data.h"
#include "voice_extension_wrapper.h"
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
        void OnEnabledSilentReminderChanged(
            const std::shared_ptr<EnabledSilentReminderCallbackData> &callbackData) override
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
        void OnApplicationInfoNeedChanged(
            const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo) override
        {
            isCallback_ = true;
        }

        ErrCode OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo)
        {
            isCallback_ = true;
            return ERR_OK;
        }

        void OnEnabledWatchStatusChanged(const uint32_t watchStatus) override
        {
            isCallback_ = true;
        }

        void OnNotificationSwitchChanged(
            const std::shared_ptr<NotificationSwitchChangedCallbackData> &callbackData) override
        {
            isCallback_ = true;
        }

        void OnSystemUpdate(const std::shared_ptr<Notification> &request) override
        {
            isCallback_ = true;
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
NotificationSubscriberManagerTest::TestAnsSubscriber NotificationSubscriberManagerTest::testAnsSubscriber_;

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
    notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr, testAnsSubscriber_.subscribedFlags_);
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
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_001, Level1)
{
    // Test NotifyUpdated function.
    const std::vector<NotificationSorting> sortingList;
    sptr<NotificationSortingMap> map = new NotificationSortingMap(sortingList);
    notificationSubscriberManager_->NotifyUpdated(map);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppName("test_bundle");
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, info, testAnsSubscriber_.subscribedFlags_),
        (int)ERR_OK);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber_, nullptr, testAnsSubscriber_.subscribedFlags_),
        (int)ERR_OK);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_002
 * @tc.name      : ANS_AddSubscriber_0100
 * @tc.desc      : Test AddSubscriber function when subscriber is nullptr, return is ERR_ANS_INNER_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_002, Level1)
{
    // Test NotifyDisturbModeChanged function.
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    int32_t uid = 200200;
    notificationSubscriberManager_->NotifyDoNotDisturbDateChanged(0, date, uid);

    // Test AddSubscriber function.
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(nullptr, info, testAnsSubscriber_.subscribedFlags_),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : NotificationSubscriberManagerTest_003
 * @tc.name      : ANS_RemoveSubscriber_0100
 * @tc.desc      : Test RemoveSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_003, Level1)
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
 * @tc.desc      : Test RemoveSubscriber function when subscriber is nullptr, return is ERR_ANS_INNER_INVALID_PARAM.
 */
HWTEST_F(NotificationSubscriberManagerTest, NotificationSubscriberManagerTest_004, Level1)
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
    ASSERT_EQ(notificationSubscriberManager_->RemoveSubscriber(nullptr, info), (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : RegisterOnSubscriberAddCallbackTest_001
 * @tc.name      : RegisterOnSubscriberAddCallback and callback is not nullptr
 * @tc.desc      : Test RegisterOnSubscriberAddCallback .
 */
void OnSubscriberAddFake(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &recode) {}
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, RegisterOnSubscriberAddCallbackTest_002, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, UnRegisterOnSubscriberAddCallbackTest_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_001, Level1)
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
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);
}

/**
 * @tc.number    : BatchNotifyConsumedInner_002
 * @tc.name      : BatchNotifyConsumedInner and params is invalid
 * @tc.desc      : Test BatchNotifyConsumedInner .
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_002, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_003, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumed_001, Level1)
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
    record->subscribedFlags_ = testAnsSubscriber->GetSubscribedFlags();
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    testAnsSubscriber->SetCallBack(false);
    notificationSubscriberManager.notificationSubQueue_ = nullptr;
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumed_subscribedFlagFalse, Level1)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    sptr<NotificationRequest> request(new NotificationRequest());
    sptr<Notification> notification(new Notification(request));
    notifications.emplace_back(notification);

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    auto record = notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscribedFlags_ = testAnsSubscriber->GetSubscribedFlags();
    notificationSubscriberManager.BatchNotifyConsumed(notifications, notificationMap, record);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : AddSubscriber001
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_001, Level1)
{
    MockGetOsAccountLocalIdFromUid(false, 0);
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));

    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(
        subscriber, nullptr, testAnsSubscriber->subscribedFlags_), (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : AddSubscriber_002
 * @tc.name      : AddSubscriber and params is nullptr
 * @tc.desc      : Test AddSubscriber .he
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriber_002, Level1)
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

    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(subscriber, info, testAnsSubscriber->subscribedFlags_),
        (int)ERR_OK);

    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    notificationSubscriberManager.NotifyUpdated(notificationMap);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);

    ASSERT_EQ(notificationSubscriberManager.RemoveSubscriber(subscriber, nullptr), (int)ERR_OK);
}

HWTEST_F(NotificationSubscriberManagerTest, NotifyUpdate_SubscribedFlagsFalse, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddDeviceType("current");
    std::vector<NotificationConstant::SlotType> slotTypes;
    slotTypes.push_back(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    info->SetSlotTypes(slotTypes);

    ASSERT_EQ(notificationSubscriberManager.AddSubscriber(subscriber, info, testAnsSubscriber->subscribedFlags_),
        (int)ERR_OK);

    sptr<NotificationSortingMap> notificationMap(new NotificationSortingMap());
    notificationSubscriberManager.NotifyUpdated(notificationMap);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    ASSERT_EQ(notificationSubscriberManager.RemoveSubscriber(subscriber, nullptr), (int)ERR_OK);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_001, Level1)
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

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_002, Level1)
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

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_003, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumed_001, Level1)
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
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    notificationSubscriberManager.NotifyConsumed(notification, notificationMap);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyBadgeEnabledChanged_001
 * @tc.name      : test notify badge enable to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyBadgeEnabledChanged_001, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    std::string bundle = "com.example.test";
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber, subscribeInfo,
        testAnsSubscriber->subscribedFlags_), (int)ERR_OK);
    sptr<EnabledNotificationCallbackData> callbackData(new EnabledNotificationCallbackData());
    callbackData->SetBundle(bundle);
    notificationSubscriberManager_->NotifyBadgeEnabledChanged(callbackData);
    notificationSubscriberManager_->WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, NotifyBadgeEnabledChanged_SubscribedFlagsFalse, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    std::string bundle = "com.example.test";
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddAppName(bundle);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber, subscribeInfo,
        testAnsSubscriber->subscribedFlags_), (int)ERR_OK);
    sptr<EnabledNotificationCallbackData> callbackData(new EnabledNotificationCallbackData());
    callbackData->SetBundle(bundle);
    notificationSubscriberManager_->NotifyBadgeEnabledChanged(callbackData);
    notificationSubscriberManager_->WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledWatchChanged_001
 * @tc.name      : test notify enabled watch changed to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledWatchChanged_001, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
    std::string bundle = "com.example.test";
    int32_t uid = 1;
    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->AddAppName(bundle);
    subscribeInfo->SetSubscriberUid(uid);
    subscribeInfo->SetIsSubscribeSelf(true);
    testAnsSubscriber->SetSubscribedFlags(
        OHOS::Notification::NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_ENABL_WATCH_CHANGED);
    ASSERT_EQ(notificationSubscriberManager_->AddSubscriber(subscriber, subscribeInfo,
        testAnsSubscriber->subscribedFlags_), (int)ERR_OK);
    uint32_t watchStatus = 1 << DistributedDeviceStatus::OWNER_FLAG;
    notificationSubscriberManager_->NotifyEnabledWatchChanged(watchStatus);
    notificationSubscriberManager_->WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : ConsumeRecordFilter_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_002, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, ConsumeRecordFilter_003, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyCanceledInner_001, Level1)
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
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    //brach need nullptr
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);

    notificationSubscriberManager.BatchNotifyCanceledInner(notifications, notificationMap, 99);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyCanceledInner_SubscribedFlagsFalse, Level1)
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
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);
    //brach need nullptr
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);

    notificationSubscriberManager.BatchNotifyCanceledInner(notifications, notificationMap, 99);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : NotifyDoNotDisturbDateChangedInner_001
 * @tc.name      : test set do not disturb date to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyDoNotDisturbDateChangedInner_001, Level1)
{
    //build notificationMap
    sptr<NotificationDoNotDisturbDate> date(new NotificationDoNotDisturbDate());
    std::string bundle = "com.example.test";
    int32_t uid = 200200;

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());

    info->AddAppUserId(101);
    info->AddAppName(bundle);
    info->SetSubscriberUid(uid);
    info->SetIsSubscribeSelf(true);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyDoNotDisturbDateChangedInner(101, date, uid);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, NotifyDoNotDisturbDateChangedInner_SubscribedFlagsFalse, Level1)
{
    //build notificationMap
    sptr<NotificationDoNotDisturbDate> date(new NotificationDoNotDisturbDate());
    std::string bundle = "com.example.test";
    int32_t uid = 200200;

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());

    info->AddAppUserId(101);
    info->AddAppName(bundle);
    info->SetSubscriberUid(uid);
    info->SetIsSubscribeSelf(true);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyDoNotDisturbDateChangedInner(101, date, uid);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}


/**
 * @tc.number    : NotifyEnabledNotificationChangedInner_002
 * @tc.name      : test enable notification changed to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledNotificationChangedInner_002, Level1)
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
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledNotificationChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledNotificationChangedInner_SubscribedFlagsFalse, Level1)
{
    //build notificationMap
    sptr<EnabledNotificationCallbackData> callback(new EnabledNotificationCallbackData());
    std::string bundle = "com.example.test";
    callback->SetBundle(bundle);
    callback->SetUid(101);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledNotificationChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledSilentReminderChangedInner_001
 * @tc.name      : test enable silent reminder changed to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledSilentReminderChangedInner_001, Level1)
{
    //build silentReminderCallbackData
    sptr<EnabledSilentReminderCallbackData> callback(new EnabledSilentReminderCallbackData());
    std::string bundle = "com.example.test";
    callback->SetBundle(bundle);
    callback->SetUid(101);
    callback->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledSilentReminderChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledSilentReminderChangedInner_002
 * @tc.name      : test enable silent reminder changed with DISABLED status
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledSilentReminderChangedInner_002, Level1)
{
    //build silentReminderCallbackData
    sptr<EnabledSilentReminderCallbackData> callback(new EnabledSilentReminderCallbackData());
    std::string bundle = "com.example.test2";
    callback->SetBundle(bundle);
    callback->SetUid(102);
    callback->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledSilentReminderChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledSilentReminderChangedInner_SubscribedFlagsFalse
 * @tc.name      : test enable silent reminder changed with invalid subscribed flags
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledSilentReminderChangedInner_SubscribedFlagsFalse, Level1)
{
    //build silentReminderCallbackData
    sptr<EnabledSilentReminderCallbackData> callback(new EnabledSilentReminderCallbackData());
    std::string bundle = "com.example.test";
    callback->SetBundle(bundle);
    callback->SetUid(101);
    callback->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.NotifyEnabledSilentReminderChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : NotifyEnabledSilentReminderChanged_001
 * @tc.name      : test notify enable silent reminder changed to trigger call back
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledSilentReminderChanged_001, Level1)
{
    //build silentReminderCallbackData
    sptr<EnabledSilentReminderCallbackData> callback(new EnabledSilentReminderCallbackData());
    std::string bundle = "com.example.test.notify";
    callback->SetBundle(bundle);
    callback->SetUid(101);
    callback->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    // This should not crash even if no subscribers are registered
    notificationSubscriberManager.NotifyEnabledSilentReminderChanged(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : SetBadgeNumber_001
 * @tc.name      : test set badge number to trigger call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, SetBadgeNumber_001, Level1)
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
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.SetBadgeNumber(badge);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, SetBadgeNumber_SubscribedFlagsFalse, Level1)
{
    //build notificationMap
    sptr<BadgeNumberCallbackData> badge(new BadgeNumberCallbackData());
    std::string bundle = "com.example.test";
    badge->SetBundle(bundle);

    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);

    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->AddAppName(bundle);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    notificationSubscriberManager.SetBadgeNumber(badge);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : NotifyApplicationInfoNeedChanged_001
 * @tc.name      :
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyApplicationInfoNeedChanged_001, Level1)
{
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyApplication(true);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationApplicationChangeInfo> changeInfo = new (std::nothrow) NotificationApplicationChangeInfo();
    notificationSubscriberManager.NotifyApplicationInfoNeedChanged(changeInfo);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, NotifyApplicationInfoNeedChanged_SubscribedFlagsFalse, Level1)
{
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyApplication(true);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationApplicationChangeInfo> changeInfo = new (std::nothrow) NotificationApplicationChangeInfo();
    notificationSubscriberManager.NotifyApplicationInfoNeedChanged(changeInfo);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : DistributeOperation_001
 * @tc.name      : test DistributeOperation call back success
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_001, Level1)
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
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr request = new (std::nothrow) NotificationRequest();
    notificationSubscriberManager.DistributeOperation(operationInfo, request);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_SubscribedFlagsFalse, Level1)
{
    sptr<NotificationOperationInfo> operationInfo(new NotificationOperationInfo);
    //build subscriber
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->SetNeedNotifyResponse(true);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr request = new (std::nothrow) NotificationRequest();
    notificationSubscriberManager.DistributeOperation(operationInfo, request);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.number    : DistributeOperation_002
 * @tc.name      : test DistributeOperation with operationInfo nullptr
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_002, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    ASSERT_EQ((int)ERR_ANS_INNER_TASK_ERR, notificationSubscriberManager.DistributeOperation(nullptr, nullptr));
}

/**
 * @tc.number    : DistributeOperation_003
 * @tc.name      : test DistributeOperation ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED
 */
HWTEST_F(NotificationSubscriberManagerTest, DistributeOperation_003, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    request->SetExtendInfo(extendInfo);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("hashCode");
    NotificationSubscriberManager notificationSubscriberManager;

    auto record = notificationSubscriberManager.CreateSubscriberRecord(nullptr);
    record->subscribedFlags_ = 0xFFFFFFFF;
    notificationSubscriberManager.subscriberRecordList_.push_back(nullptr);
    notificationSubscriberManager.subscriberRecordList_.push_back(record);
    ASSERT_EQ((int)ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED,
        notificationSubscriberManager.DistributeOperation(operationInfo, request));
}

/**
 * @tc.number    : OnRemoteDied_001
 * @tc.name      : OnRemoteDied and params is nullptr
 * @tc.desc      : Test OnRemoteDied .
 */
HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_002, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_003, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_004, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
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
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_005, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
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
HWTEST_F(NotificationSubscriberManagerTest, GetIsEnableEffectedRemind_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, GetIsEnableEffectedRemind_002, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeSubscriberd_001, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeSubscriberd_002, Level1)
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
HWTEST_F(NotificationSubscriberManagerTest, IsDeviceTypeAffordConsume_001, Level1)
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
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_subscribeControlIsTrue, Level1)
{
    EXTENTION_WRAPPER->subscribeControl_ = nullptr;

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
    record->isSubscribeSelf = false;

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_TRUE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_subscribeControlIsFalse, Level1)
{
    EXTENTION_WRAPPER->subscribeControl_ = [](const std::string &bundleName, NotificationConstant::SlotType slotType) {
        if (bundleName == "subscriberManagerTestBundleName") {
            return true;
        }
        return false;
    };

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
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = false;

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_FALSE(res);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedBysubscriber_subscribeSalfAndSubscriberControlIsTrue, Level1)
{
    EXTENTION_WRAPPER->subscribeControl_ = [](const std::string &bundleName, NotificationConstant::SlotType slotType) {
        if (bundleName == "subscriberManagerTestBundleName") {
            return true;
        }
        return false;
    };

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
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;

    sptr<NotificationSubscribeInfo> subscribeInfo(new NotificationSubscribeInfo());
    subscribeInfo->SetSubscriberUid(101);
    subscribeInfo->AddAppUserId(101);
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
    auto res = notificationSubscriberManager.IsSubscribedBysubscriber(record, notification);
    ASSERT_TRUE(res);
}
#endif // DEBUG

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_Normal, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*notificationFlagsOfDevices)["testDevice"] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification = new Notification(request);

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_DeviceTypeNotMatch, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = request->GetFlags();
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testAnotherDevice";
    EXPECT_FALSE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_FlagsMapNull, Level1)
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
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_FlagsMapEmpty, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_DeviceTypeMatchedButNullDeviceFlag, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::PC_DEVICE_TYPE;
    EXPECT_FALSE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_CheckConsumedDeviceAndThirdPartyDevice, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE;
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, true));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_CheckConsumedDeviceAndUnconsumed, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::PC_DEVICE_TYPE;
    EXPECT_FALSE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, true));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_CheckConsumedDeviceAndConsumed, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    request->AddConsumedDevices(NotificationConstant::PC_DEVICE_TYPE);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::PC_DEVICE_TYPE;
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, true));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_DeviceTypeEmpty, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "";
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false));
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_CurrentDeviceType, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
    make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    bool result = notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false);
    EXPECT_TRUE(result);
}

HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_RequestNull, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));
    notification->request_ = nullptr;

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    bool result = notificationSubscriberManager.IsSubscribedByDeviceType(record, notification, false);
    EXPECT_FALSE(result);
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_Normal, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*notificationFlagsOfDevices)["testDevice"] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_NE(nullptr, resultRequest);
    EXPECT_EQ(123, resultRequest->GetFlags()->GetReminderFlags());
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_StubSubscriber, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*notificationFlagsOfDevices)["testDevice"] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";

    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_EQ(nullptr, result);
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_DeviceFlagsEmpty, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_EQ(nullptr, resultRequest->GetFlags());
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_DeviceTypeEmpty, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*notificationFlagsOfDevices)["testDevice"] = flags;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_EQ(nullptr, resultRequest->GetFlags());
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_NullNotification, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, nullptr);

    EXPECT_EQ(nullptr, result);
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_NullRequest, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification(new Notification(request));
    notification->request_ = nullptr;

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_EQ(nullptr, result);
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_DeviceTypeMatchedButNullDeviceFlag, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    (*notificationFlagsOfDevices)["testDevice"] = nullptr;
    request->SetDeviceFlags(notificationFlagsOfDevices);
    sptr<Notification> notification(new Notification(request));

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testAnotherDevice";

    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_EQ(nullptr, resultRequest->GetFlags());
}
#else
HWTEST_F(NotificationSubscriberManagerTest, IsSubscribedByDeviceType_UndefinedSmartReminderSupported, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    EXPECT_TRUE(notificationSubscriberManager.IsSubscribedByDeviceType(nullptr, nullptr, true));
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_Normal, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    request->SetFlags(flags);
    sptr<Notification> notification(new Notification(request));
    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";

    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_NE(nullptr, resultRequest);
    EXPECT_EQ(123, resultRequest->GetFlags()->GetReminderFlags());
}

HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_StubSubscriber, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    request->SetFlags(flags);
    sptr<Notification> notification(new Notification(request));

    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->isSubscribeSelf = true;
    record->deviceType = "testDevice";

    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);

    EXPECT_EQ(nullptr, result);
}
#endif
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_ResetPriority, Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    request->SetInnerPriorityNotificationType(NotificationConstant::PriorityNotificationType::KEY_PROGRESS);
    sptr<Notification> notification(new Notification(request));
    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "tablet";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record, notification);
    EXPECT_NE(nullptr, result);
    sptr<NotificationRequest> resultRequest = result->GetNotificationRequestPoint();
    EXPECT_NE(nullptr, resultRequest);
    EXPECT_EQ(resultRequest->GetPriorityNotificationType(), NotificationConstant::PriorityNotificationType::OTHER);
}
#endif

/**
 * @tc.name: GetVoiceContentInfo_00001
 * @tc.desc: Test GetVoiceContentInfo with null request.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;
    sptr<Notification> notification = new Notification(request);
    notification->request_ = nullptr;
    std::set<std::string> voiceFlag;
    std::string content;
    NotificationSubscriberManager notificationSubscriberManager;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetVoiceContentInfo_00002
 * @tc.desc: Test GetVoiceContentInfo with empty device flags.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    std::set<std::string> voiceFlag;
    std::string content;
    NotificationSubscriberManager notificationSubscriberManager;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
    EXPECT_TRUE(content.empty());
}

/**
 * @tc.name: GetVoiceContentInfo_00003
 * @tc.desc: Test GetVoiceContentInfo with valid device flags but no subscriber.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);
    std::set<std::string> voiceFlag;
    std::string content;
    NotificationSubscriberManager notificationSubscriberManager;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
}

/**
 * @tc.name: GetVoiceContentInfo_00004
 * @tc.desc: Test GetVoiceContentInfo with subscriber but no voice flag.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->deviceType = "tablet";
    record->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CONSUMED;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    std::set<std::string> voiceFlag;
    std::string content;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
}

/**
 * @tc.name: GetVoiceContentInfo_00005
 * @tc.desc: Test GetVoiceContentInfo with voice flag subscriber.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00005, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->deviceType = "tablet";
    record->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT |
        NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CONSUMED;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    std::set<std::string> voiceFlag;
    std::string content;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_TRUE(result == ERR_OK || result != ERR_OK);
}

/**
 * @tc.name: GenerateSubscribedNotification_WithVoiceContent_00001
 * @tc.desc: Test GenerateSubscribedNotification with voice content.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_WithVoiceContent_00001,
    Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    std::string voiceContent = "Test voice content";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record,
        notification, voiceContent);

EXPECT_NE(nullptr, result);
    EXPECT_NE(nullptr, result->GetVoiceContent());
    EXPECT_EQ(result->GetVoiceContent()->GetTextContent(), voiceContent);
}

/**
 * @tc.name: NotifyConsumedInner_006
 * @tc.desc: Test NotifyConsumedInner with enableClassification=true subscriber
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_006, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetEnableClassification(true);
    notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    auto isCall = subscriber->IsCalled();
    ASSERT_TRUE(isCall);
    NotificationClassificationMgr::GetInstance().Clear();
}

/**
 * @tc.name: BatchNotifyConsumedInner_004
 * @tc.desc: Test BatchNotifyConsumedInner with enableClassification=true and ClassificationMgr pre-populated
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, BatchNotifyConsumedInner_004, Level1)
{
    sptr<MockAnsSubscriber> mockSubscriber = new MockAnsSubscriber(new MockIRemoteObject());
    EXPECT_CALL(*mockSubscriber, OnConsumedList(_, _)).Times(1);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("test");
    request->SetNotificationId(1);
    sptr<Notification> notification = new Notification(request);

    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    NotificationClassificationMgr::GetInstance().AddOrUpdate(notification->GetKey(), classification);

    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    notifications.emplace_back(nullptr);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();

    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager_->CreateSubscriberRecord(mockSubscriber);
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppName("test");
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetEnableClassification(true);
    notificationSubscriberManager_->AddRecordInfo(record, subscribeInfo);
    notificationSubscriberManager_->BatchNotifyConsumedInner(notifications, notificationMap, record);

    NotificationClassificationMgr::GetInstance().Clear();
}

/**
 * @tc.name: AddSubscriberInner_NeedSilentReplayOnSubscribe_001
 * @tc.desc: Test AddSubscriberInner calls onSubscriberAddCallback_ when needSilentReplayOnSubscribe=true
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriberInner_NeedSilentReplayOnSubscribe_001, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    bool callbackCalled = false;
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        [&callbackCalled](const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &record) {
            callbackCalled = true;
        };
    notificationSubscriberManager.RegisterOnSubscriberAddCallback(callback);

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetNeedSilentReplayOnSubscribe(true);

    ErrCode result = notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    ASSERT_EQ(result, ERR_OK);
    ASSERT_TRUE(callbackCalled);
}

/**
 * @tc.name: AddSubscriberInner_NeedSilentReplayOnSubscribe_002
 * @tc.desc: Test AddSubscriberInner does NOT call onSubscriberAddCallback_ when needSilentReplayOnSubscribe=false
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriberInner_NeedSilentReplayOnSubscribe_002, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    bool callbackCalled = false;
    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        [&callbackCalled](const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &record) {
            callbackCalled = true;
        };
    notificationSubscriberManager.RegisterOnSubscriberAddCallback(callback);

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetNeedSilentReplayOnSubscribe(false);

    ErrCode result = notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    ASSERT_EQ(result, ERR_OK);
    ASSERT_FALSE(callbackCalled);
}

/**
 * @tc.name: AddSubscriberInner_NeedSilentReplayOnSubscribe_003
 * @tc.desc: Test AddSubscriberInner does NOT call callback when
 *          needSilentReplayOnSubscribe=true but callback is nullptr
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriberInner_NeedSilentReplayOnSubscribe_003, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetNeedSilentReplayOnSubscribe(true);

    ErrCode result = notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AddSubscriberInner_EnableClassification_001
 * @tc.desc: Test HasAggregationSubscriber is true when AddSubscriberInner enableClassification=true
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriberInner_EnableClassification_001, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetEnableClassification(true);

    ErrCode result = notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    ASSERT_EQ(result, ERR_OK);
    EXPECT_TRUE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: AddSubscriberInner_EnableClassification_002
 * @tc.desc: Test HasAggregationSubscriber stays false when enableClassification=false
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, AddSubscriberInner_EnableClassification_002, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetEnableClassification(false);

    ErrCode result = notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo);

    ASSERT_EQ(result, ERR_OK);
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: OnRemoteDied_EnableClassificationTrue
 * @tc.desc: Test HasAggregationSubscriber becomes false after OnRemoteDied when enableClassification=true
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_EnableClassificationTrue, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.notificationSubQueue_ = std::make_shared<ffrt::queue>("test");
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberUid = 456;
    record->enableClassification = true;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    EXPECT_TRUE(notificationSubscriberManager.HasAggregationSubscriber());
    notificationSubscriberManager.OnRemoteDied(subscriber->AsObject());

    EXPECT_EQ(notificationSubscriberManager.subscriberRecordList_.size(), 0);
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: OnRemoteDied_EnableClassificationFalse
 * @tc.desc: Test HasAggregationSubscriber stays false after OnRemoteDied when enableClassification=false
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, OnRemoteDied_EnableClassificationFalse, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    notificationSubscriberManager.notificationSubQueue_ = std::make_shared<ffrt::queue>("test");
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberUid = 457;
    record->enableClassification = false;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());
    notificationSubscriberManager.OnRemoteDied(subscriber->AsObject());

    EXPECT_EQ(notificationSubscriberManager.subscriberRecordList_.size(), 0);
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: HasAggregationSubscriber_001
 * @tc.desc: Test HasAggregationSubscriber reflects the subscriber record list state
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, HasAggregationSubscriber_001, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());

    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0);
    subscribeInfo->SetEnableClassification(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, subscribeInfo), ERR_OK);
    EXPECT_TRUE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: HasAggregationSubscriber_ResubscribeFlip
 * @tc.desc: Test HasAggregationSubscriber follows enableClassification transitions on re-subscribe
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, HasAggregationSubscriber_ResubscribeFlip, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<MockAnsSubscriberTest> subscriber(new (std::nothrow) MockAnsSubscriberTest(new MockIRemoteObject()));

    auto makeInfo = [](bool enable) {
        const sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
        info->AddAppUserId(SUBSCRIBE_USER_ALL);
        info->SetSubscribedFlags(0);
        info->SetEnableClassification(enable);
        return info;
    };

    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, makeInfo(true)), ERR_OK);
    EXPECT_TRUE(notificationSubscriberManager.HasAggregationSubscriber());

    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, makeInfo(false)), ERR_OK);
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());

    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, makeInfo(true)), ERR_OK);
    EXPECT_TRUE(notificationSubscriberManager.HasAggregationSubscriber());

    ASSERT_EQ(notificationSubscriberManager.RemoveSubscriberInner(subscriber, nullptr), ERR_OK);
    EXPECT_FALSE(notificationSubscriberManager.HasAggregationSubscriber());
}

/**
 * @tc.name: NotifySystemUpdate_001
 * @tc.desc: Test NotifySystemUpdateInner with nullptr notification returns early
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifySystemUpdate_001, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<Notification> notification = nullptr;
    sptr<NotificationClassification> classification = nullptr;

    notificationSubscriberManager.NotifySystemUpdateInner(notification, classification);

    ASSERT_EQ(notification, nullptr);
}

/**
 * @tc.name: NotifySystemUpdate_002
 * @tc.desc: Test NotifySystemUpdate with notification and classification (enableClassification=true)
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifySystemUpdate_002, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(SUBSCRIBE_USER_ALL);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    info->SetEnableClassification(true);
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");

    notificationSubscriberManager.NotifySystemUpdate(notification, classification);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.name: NotifySystemUpdate_003
 * @tc.desc: Test NotifySystemUpdate with notification only (default nullptr classification)
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifySystemUpdate_003, Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(SUBSCRIBE_USER_ALL);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(DEFAULT_UID);
    request->SetOwnerBundleName("test1");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);

    notificationSubscriberManager.NotifySystemUpdate(notification);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.name: NotifyNotificationSwitchChanged_001
 * @tc.desc: Test NotifyNotificationSwitchChanged with valid callback data triggers callback
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyNotificationSwitchChanged_001, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    testAnsSubscriber->SetSubscribedFlags(
        NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_NOTIFICATION_SWITCH_CHANGED);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationSwitchChangedCallbackData> callbackData =
        new NotificationSwitchChangedCallbackData("DEAL", 100,
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    notificationSubscriberManager.NotifyNotificationSwitchChanged(callbackData);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_TRUE(isCallback);
}

/**
 * @tc.name: NotifyNotificationSwitchChanged_002
 * @tc.desc: Test NotifyNotificationSwitchChanged with subscribedFlags not including SWITCH_CHANGED
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyNotificationSwitchChanged_002, Level1)
{
    std::shared_ptr<TestAnsSubscriber> testAnsSubscriber = std::make_shared<TestAnsSubscriber>();
    testAnsSubscriber->SetSubscribedFlags(0);
    sptr<IAnsSubscriber> subscriber(new (std::nothrow) SubscriberListener(testAnsSubscriber));
    auto isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);

    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSubscribeInfo> info(new NotificationSubscribeInfo());
    info->AddAppUserId(100);
    info->SetSubscribedFlags(testAnsSubscriber->GetSubscribedFlags());
    ASSERT_EQ(notificationSubscriberManager.AddSubscriberInner(subscriber, info), (int)ERR_OK);

    sptr<NotificationSwitchChangedCallbackData> callbackData =
        new NotificationSwitchChangedCallbackData("DEAL", 100,
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    notificationSubscriberManager.NotifyNotificationSwitchChanged(callbackData);
    notificationSubscriberManager.WaitForFfrtQueue();
    isCallback = testAnsSubscriber->GetCallBack();
    ASSERT_FALSE(isCallback);
}

/**
 * @tc.name: GenerateSubscribedNotification_WithEmptyVoiceContent_00001
 * @tc.desc: Test GenerateSubscribedNotification with empty voice content.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_WithEmptyVoiceContent_00001,
    Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    std::string voiceContent = "";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record,
        notification, voiceContent);

    EXPECT_NE(nullptr, result);
    EXPECT_EQ(nullptr, result->GetVoiceContent());
}

/**
 * @tc.name: GetVoiceContentInfo_00006
 * @tc.desc: Test GetVoiceContentInfo with CURRENT_DEVICE_TYPE subscriber (continue branch).
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00006, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    record->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    std::set<std::string> voiceFlag;
    std::string content;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
}

/**
 * @tc.name: GetVoiceContentInfo_00007
 * @tc.desc: Test GetVoiceContentInfo with device flags but no matching device type.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00007, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["phone"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->deviceType = "tablet";
    record->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    notificationSubscriberManager.subscriberRecordList_.push_back(record);

    std::set<std::string> voiceFlag;
    std::string content;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
}

/**
 * @tc.name: GetVoiceContentInfo_00008
 * @tc.desc: Test GetVoiceContentInfo with valid flags size.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00008, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    (*flagsMap)["phone"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    std::set<std::string> voiceFlag;
    std::string content;
    NotificationSubscriberManager notificationSubscriberManager;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(voiceFlag.empty());
    EXPECT_EQ(flagsMap->size(), 2);
}

/**
 * @tc.name: GetVoiceContentInfo_00009
 * @tc.desc: Test GetVoiceContentInfo with multiple subscribers and mixed device types.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GetVoiceContentInfo_00009, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto flagsMap = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(123);
    (*flagsMap)["tablet"] = flags;
    request->SetDeviceFlags(flagsMap);
    sptr<Notification> notification = new Notification(request);

    NotificationSubscriberManager notificationSubscriberManager;

    sptr<IAnsSubscriber> subscriber1 = new MockAnsSubscriber(new MockIRemoteObject());
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record1 =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber1);
    record1->deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    record1->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    notificationSubscriberManager.subscriberRecordList_.push_back(record1);

    sptr<IAnsSubscriber> subscriber2 = new MockAnsSubscriber(new MockIRemoteObject());
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record2 =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber2);
    record2->deviceType = "tablet";
    record2->subscribedFlags_ = NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_VOICE_CONTENT;
    notificationSubscriberManager.subscriberRecordList_.push_back(record2);

    std::set<std::string> voiceFlag;
    std::string content;
    int32_t result = notificationSubscriberManager.GetVoiceContentInfo(notification, voiceFlag, content);
    EXPECT_TRUE(result == ERR_OK || result != ERR_OK);
    if (result == ERR_OK && !voiceFlag.empty()) {
        EXPECT_TRUE(voiceFlag.count("tablet"));
    }
}

/**
 * @tc.name: GenerateSubscribedNotification_WithVoiceContent_00002
 * @tc.desc: Test GenerateSubscribedNotification with voice content text.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_WithVoiceContent_00002,
    Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    std::string voiceContent = "这是一个测试播报内容";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record,
        notification, voiceContent);

    EXPECT_NE(nullptr, result);
    EXPECT_NE(nullptr, result->GetVoiceContent());
    EXPECT_EQ(result->GetVoiceContent()->GetTextContent(), voiceContent);
}

/**
 * @tc.name: GenerateSubscribedNotification_WithVoiceContent_00003
 * @tc.desc: Test GenerateSubscribedNotification with long voice content.
 * @tc.type: FUNC
 * @tc.require: I8I6KX
 */
HWTEST_F(NotificationSubscriberManagerTest, GenerateSubscribedNotification_WithVoiceContent_00003,
    Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUserId(101);
    request->SetCreatorUid(101);
    sptr<Notification> notification = new Notification(request);

    sptr<IAnsSubscriber> subscriber = new MockAnsSubscriber(new MockIRemoteObject());
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(subscriber);
    record->subscriberBundleName_ = "subscriberManagerTestBundleName";
    record->deviceType = "testDevice";

    std::string voiceContent =
        "这是一段很长的测试播报内容，用于验证系统对长文本的处理能力";
    sptr<Notification> result = notificationSubscriberManager.GenerateSubscribedNotification(record,
        notification, voiceContent);

    EXPECT_NE(nullptr, result);
    EXPECT_NE(nullptr, result->GetVoiceContent());
    EXPECT_EQ(result->GetVoiceContent()->GetTextContent(), voiceContent);
}

/**
 * @tc.number    : NotifyBadgeEnabledChangedInner_InvalidUserId_001
 * @tc.name      : test NotifyBadgeEnabledChangedInner returns early when uid resolves to invalid userId
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyBadgeEnabledChangedInner_InvalidUserId_001, Level1)
{
    sptr<EnabledNotificationCallbackData> callback(new EnabledNotificationCallbackData());
    callback->SetBundle("com.example.test");
    callback->SetUid(101);

    NotificationSubscriberManager notificationSubscriberManager;
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    notificationSubscriberManager.NotifyBadgeEnabledChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
    EXPECT_NE(callback, nullptr);
}

/**
 * @tc.number    : NotifyEnabledNotificationChangedInner_InvalidUserId_001
 * @tc.name      : test NotifyEnabledNotificationChangedInner returns early when uid resolves to invalid userId
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledNotificationChangedInner_InvalidUserId_001, Level1)
{
    sptr<EnabledNotificationCallbackData> callback(new EnabledNotificationCallbackData());
    callback->SetBundle("com.example.test");
    callback->SetUid(101);

    NotificationSubscriberManager notificationSubscriberManager;
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    notificationSubscriberManager.NotifyEnabledNotificationChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
    EXPECT_NE(callback, nullptr);
}

/**
 * @tc.number    : NotifyEnabledSilentReminderChangedInner_InvalidUserId_001
 * @tc.name      : test NotifyEnabledSilentReminderChangedInner returns early when uid resolves to invalid userId
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyEnabledSilentReminderChangedInner_InvalidUserId_001, Level1)
{
    sptr<EnabledSilentReminderCallbackData> callback(new EnabledSilentReminderCallbackData());
    callback->SetBundle("com.example.test");
    callback->SetUid(101);

    NotificationSubscriberManager notificationSubscriberManager;
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    notificationSubscriberManager.NotifyEnabledSilentReminderChangedInner(callback);
    notificationSubscriberManager.WaitForFfrtQueue();
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
    EXPECT_NE(callback, nullptr);
}

/**
 * @tc.number    : SetBadgeNumber_InvalidUserId_001
 * @tc.name      : test SetBadgeNumber lambda returns early when uid resolves to invalid userId
 */
HWTEST_F(NotificationSubscriberManagerTest, SetBadgeNumber_InvalidUserId_001, Level1)
{
    sptr<BadgeNumberCallbackData> badge(new BadgeNumberCallbackData());
    badge->SetBundle("com.example.test");
    badge->SetUid(101);

    NotificationSubscriberManager notificationSubscriberManager;
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    notificationSubscriberManager.SetBadgeNumber(badge);
    notificationSubscriberManager.WaitForFfrtQueue();
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
    EXPECT_NE(badge, nullptr);
}
}  // namespace Notification
}  // namespace OHOS

// ---------------------------------------------------------------------------
// FIX-9b appended (TEST-01 / AC-005 / AC-006 / AC-015): the semantic assertions of the
// synchronous consumption path arbitration (NotifyConsumedInner). The existing smoke
// cases above only assert that the subscriber callback fires; the two cases below
// preset the classification cache state and assert what the consumption chain actually
// distributes: the effective value of the arbitration (the cached landed value for the
// drop family, the landed fresh triple for APPLY) plus the request type restore. The
// cases reuse the smoke case skeleton (the stack manager instance, the mock ans
// subscriber and the direct NotifyConsumedInner call). The wrapper stays uninitialized
// for the drop family case (dlopen fails, the classification stays null: exactly the
// null round boundary), while the APPLY case injects a fake update function pointer so
// one fresh triple is handed over (the in process .so contract), restored to the
// pristine null pointer right after the call. Everything below is guarded by the
// priority feature macro, matching the conditional define of this target.
// ---------------------------------------------------------------------------
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
#include <chrono>
#include <cstdint>

#include "notification_constant.h"
#include "priority_notification_degrade_manager.h"
#endif

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
namespace {
constexpr int64_t SUB_MGR_TEST_HOUR_MILLIS = 3600LL * 1000LL;
constexpr int32_t SUB_MGR_TEST_UID = 200300;

const std::string SUB_MGR_TEST_TYPE_URGENT = NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
const std::string SUB_MGR_TEST_TYPE_AT_ME = NotificationConstant::PriorityNotificationType::AT_ME;
const std::string SUB_MGR_TEST_TYPE_OTHER = NotificationConstant::PriorityNotificationType::OTHER;
const int32_t SUB_MGR_TEST_SOURCE_AI = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI);
const int32_t SUB_MGR_TEST_SOURCE_KEYWORD =
    static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD);

int64_t SubMgrTestNowMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

// A request the consumption path accepts (the smoke case shape: a social notification
// with normal content, so the stub round trip stays parcelable), carrying the bundle
// identity the wrapper command building and the degrade registration key by.
sptr<NotificationRequest> SubMgrTestMakeRequest(const std::string &bundleName)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetNotificationId(9100);
    request->SetCreatorBundleName(bundleName);
    request->SetCreatorUid(SUB_MGR_TEST_UID);
    request->SetOwnerBundleName("");
    request->SetOwnerUid(SUB_MGR_TEST_UID);
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    return request;
}

// Bundle level preference control through the real preferences singleton (the way the
// priority helper cases steer the bundle filter of the wrapper command building).
// PRIORITY_STRATEGY_INTELLIGENT carries no STATUS_ALL_PRIORITY bit, so the request
// passes the filter.
void SubMgrTestPutBundlePreference(const std::string &bundleName)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, SUB_MGR_TEST_UID);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(
        bundleOption, PRIORITY_STRATEGY_INTELLIGENT);
}

void SubMgrTestExpectPriorityInfo(const NotificationClassification::PriorityInfo &priorityInfo,
    const std::string &type, int64_t expiredTime, int32_t source)
{
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), type);
    EXPECT_EQ(priorityInfo.GetExpiredTime(), expiredTime);
    EXPECT_EQ(priorityInfo.GetSource(), source);
}

// Cleans the classification cache and resets the degrade manager singleton so every
// case starts from a new lifecycle and leaves nothing behind for the later cases.
void SubMgrTestResetPriorityState()
{
    NotificationClassificationMgr::GetInstance().Clear();
    PriorityNotificationDegradeManager::DestroyInstance();
}

// A subscriber capturing the classification the server attached to the consumed
// notification stub (the shape the classification distribution is observable through).
class SubMgrTestClassificationSubscriber : public MockAnsSubscriber {
public:
    explicit SubMgrTestClassificationSubscriber(const sptr<IRemoteObject> &remote) : MockAnsSubscriber(remote) {};

    ErrCode OnConsumed(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override
    {
        isCalled_ = true;
        if (notification != nullptr) {
            lastClassification_ = notification->GetNotificationClassification();
        }
        return ERR_OK;
    }

    ErrCode OnConsumed(const sptr<Notification> &notification) override
    {
        isCalled_ = true;
        return ERR_OK;
    }

    bool IsCalled() const
    {
        return isCalled_;
    }

    sptr<NotificationClassification> GetLastClassification() const
    {
        return lastClassification_;
    }

private:
    bool isCalled_ {false};
    sptr<NotificationClassification> lastClassification_ {nullptr};
};

// Registers the classification capturing subscriber with every consumption flag and
// the classification distribution enabled (the registration goes through the inner
// entry, no IPC side paths).
sptr<SubMgrTestClassificationSubscriber> SubMgrTestRegisterSubscriber(
    NotificationSubscriberManager &manager)
{
    sptr<SubMgrTestClassificationSubscriber> subscriber(
        new SubMgrTestClassificationSubscriber(new MockIRemoteObject()));
    const sptr<NotificationSubscribeInfo> subscribeInfo = new NotificationSubscribeInfo();
    subscribeInfo->AddAppUserId(SUBSCRIBE_USER_ALL);
    subscribeInfo->SetSubscribedFlags(0xFFFFFFFF);
    subscribeInfo->SetEnableClassification(true);
    EXPECT_EQ(manager.AddSubscriberInner(subscriber, subscribeInfo), ERR_OK);
    return subscriber;
}

// The fake closed source round of the APPLY case: the real .so never loads in the unit
// test environment (dlopen fails and the classification slot stays null), so the
// landing of a fresh triple on the consumption path is only reachable through an
// injected stand in function pointer. The fake mirrors the in process contract of the
// real entry: it writes its round decision type into the request and returns the fresh
// triple through the classification slot, and snapshots the triple so the assertions
// compare against exactly what was handed over.
NotificationClassification::PriorityInfo g_subMgrFakedPriorityInfo;

int32_t SubMgrTestFakeUpdateNotification(const std::vector<sptr<NotificationRequest>> &requests,
    const std::vector<nlohmann::json> &commands,
    std::vector<sptr<NotificationClassification>> &notificationClassifications,
    std::vector<int32_t> &results)
{
    if (requests.empty() || notificationClassifications.empty()) {
        return NotificationAiExtensionWrapper::ErrorCode::ERR_FAIL;
    }
    requests[0]->SetInnerPriorityNotificationType(SUB_MGR_TEST_TYPE_AT_ME);
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(SUB_MGR_TEST_TYPE_AT_ME);
    priorityInfo.SetExpiredTime(SubMgrTestNowMillis() + 2 * SUB_MGR_TEST_HOUR_MILLIS);
    priorityInfo.SetSource(SUB_MGR_TEST_SOURCE_AI);
    classification->SetPriorityInfo(priorityInfo);
    notificationClassifications[0] = classification;
    g_subMgrFakedPriorityInfo = priorityInfo;
    return NotificationAiExtensionWrapper::ErrorCode::ERR_OK;
}
} // namespace

/**
 * @tc.name: NotifyConsumedInner_PriorityNullClear_001
 * @tc.desc: Test the null round clear semantics of the consumption path arbitration
 *           (overwrite semantics): with the cache holding a determined rule triple, a
 *           consumption round (a null classification, the wrapper unavailable shape)
 *           clears the cached triple to the default (the aggregation labels kept),
 *           forces the request type to OTHER, strips the stale registration and the
 *           subscriber receives the reset value as the effective classification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_PriorityNullClear_001, Level1)
{
    SubMgrTestResetPriorityState();
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<SubMgrTestClassificationSubscriber> subscriber = SubMgrTestRegisterSubscriber(notificationSubscriberManager);

    sptr<NotificationRequest> request = SubMgrTestMakeRequest("com.example.subscriber.dropfamily");
    sptr<Notification> notification = new Notification(request);
    std::string notificationKey = notification->GetKey();
    // The cache holds a determined rule triple landed through the real arbitration
    // entry (a future expire time keeps the preset on the registration path only).
    int64_t expireTime = SubMgrTestNowMillis() + SUB_MGR_TEST_HOUR_MILLIS;
    request->SetInnerPriorityNotificationType(SUB_MGR_TEST_TYPE_URGENT);
    sptr<NotificationClassification> preset = new NotificationClassification("DEAL", "LOGISTICS");
    NotificationClassification::PriorityInfo presetInfo;
    presetInfo.SetPriorityNotificationType(SUB_MGR_TEST_TYPE_URGENT);
    presetInfo.SetExpiredTime(expireTime);
    presetInfo.SetSource(SUB_MGR_TEST_SOURCE_KEYWORD);
    preset->SetPriorityInfo(presetInfo);
    sptr<NotificationClassification> presetEffective = nullptr;
    ASSERT_EQ(PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(notificationKey,
        notification->GetNotificationRequestPoint(), preset, presetEffective),
        PriorityNotificationDegradeManager::ArbitrateResult::APPLY);
    // The closed source wrote its own type into the request this round (either kept
    // when the intelligent switch read fails early, or the OTHER of the reset before
    // the wrapper call): the null round clear below forces both shapes to OTHER.
    request->SetInnerPriorityNotificationType(SUB_MGR_TEST_TYPE_AT_ME);

    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);

    // The subscriber got the consumed notification with the effective classification:
    // null, the round's landed value (the cache entry was removed by the overwrite).
    ASSERT_TRUE(subscriber->IsCalled());
    EXPECT_EQ(subscriber->GetLastClassification(), nullptr);
    // The request type was forced to OTHER inside the arbitration (no priority survives).
    EXPECT_EQ(notification->GetNotificationRequestPoint()->GetPriorityNotificationType(),
        SUB_MGR_TEST_TYPE_OTHER);
    // The cache entry is removed and the stale registration is stripped.
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(notificationKey), nullptr);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), 0);

    notificationSubscriberManager.RemoveSubscriberInner(subscriber, nullptr);
    SubMgrTestResetPriorityState();
}

/**
 * @tc.name: NotifyConsumedInner_PriorityApplyNewValue_001
 * @tc.desc: Test the APPLY semantics of the consumption path arbitration (AC-006,
 *           T004): with no cached classification, a consumption round carrying a fresh
 *           triple (delivered through the injected fake closed source round, since the
 *           real .so never loads here) lands the triple, registers the degrade and
 *           distributes the landed new value to the subscriber.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberManagerTest, NotifyConsumedInner_PriorityApplyNewValue_001, Level1)
{
    SubMgrTestResetPriorityState();
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<SubMgrTestClassificationSubscriber> subscriber = SubMgrTestRegisterSubscriber(notificationSubscriberManager);

    // Steer the wrapper command building so the closed source round is actually
    // reached: the intelligent switch on, the bundle enabled and an intelligent
    // strategy (no STATUS_ALL_PRIORITY bit).
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    std::string bundleName = "com.example.subscriber.applynewvalue";
    SubMgrTestPutBundlePreference(bundleName);
    sptr<NotificationRequest> request = SubMgrTestMakeRequest(bundleName);
    sptr<Notification> notification = new Notification(request);
    std::string notificationKey = notification->GetKey();
    // The fake closed source round hands over a fresh triple and writes its type into
    // the request (the in process contract); the pristine wrapper state (the dlopen
    // failure leaves the pointer null) is restored right after the call.
    NOTIFICATION_AI_EXTENSION_WRAPPER->updateNotification_ = SubMgrTestFakeUpdateNotification;
    g_subMgrFakedPriorityInfo = NotificationClassification::PriorityInfo();

    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    notificationSubscriberManager.NotifyConsumedInner(notification, notificationMap);
    NOTIFICATION_AI_EXTENSION_WRAPPER->updateNotification_ = nullptr;

    // The fake round actually ran (otherwise the snapshot below stays the default
    // triple and the following assertions fail loudly).
    ASSERT_EQ(g_subMgrFakedPriorityInfo.GetPriorityNotificationType(), SUB_MGR_TEST_TYPE_AT_ME);
    // The subscriber got the consumed notification with the landed new value.
    ASSERT_TRUE(subscriber->IsCalled());
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    ASSERT_NE(received, nullptr);
    SubMgrTestExpectPriorityInfo(received->GetPriorityInfo(),
        g_subMgrFakedPriorityInfo.GetPriorityNotificationType(),
        g_subMgrFakedPriorityInfo.GetExpiredTime(), g_subMgrFakedPriorityInfo.GetSource());
    EXPECT_EQ(received->GetClassification(), "DEAL");
    EXPECT_EQ(received->GetSubClassification(), "LOGISTICS");
    // The fresh type the closed source wrote stays (APPLY never restores) and the
    // triple landed into the cache with the degrade registration armed for it.
    EXPECT_EQ(notification->GetNotificationRequestPoint()->GetPriorityNotificationType(),
        SUB_MGR_TEST_TYPE_AT_ME);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    ASSERT_NE(landed, nullptr);
    SubMgrTestExpectPriorityInfo(landed->GetPriorityInfo(),
        g_subMgrFakedPriorityInfo.GetPriorityNotificationType(),
        g_subMgrFakedPriorityInfo.GetExpiredTime(), g_subMgrFakedPriorityInfo.GetSource());
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(),
        g_subMgrFakedPriorityInfo.GetExpiredTime());

    // Restore the factory intelligent switch default for the later cases.
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    notificationSubscriberManager.RemoveSubscriberInner(subscriber, nullptr);
    SubMgrTestResetPriorityState();
}
#endif // ANS_FEATURE_PRIORITY_NOTIFICATION
}  // namespace Notification
}  // namespace OHOS

