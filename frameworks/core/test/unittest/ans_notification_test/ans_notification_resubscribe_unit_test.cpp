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

#include <functional>
#include <gtest/gtest.h>

#define private public // NOLINT
#define protected public // NOLINT
#include "ans_notification.h"
#include "ans_manager_death_recipient.h"
#include "ans_subscriber_proxy.h"
#include "ans_manager_proxy.h"
#include "iservice_registry.h"
#include "notification_subscriber.h"
#undef private
#undef protected
#define private public // NOLINT
#include "mock_service_registry.h"
#undef private
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "system_ability_definition.h"
#include "mock_ans_manager_proxy.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace OHOS {
namespace Notification {
class AnsNotificationResubscribeUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
    std::shared_ptr<AnsNotification> ans_;
    sptr<MockAnsManagerProxy> mockProxy_;
    sptr<MockSystemAbilityManager> mockSAMgr_;
    void SetMockProxy()
    {
        mockProxy_ = sptr<MockAnsManagerProxy>(new MockAnsManagerProxy());
        ON_CALL(*mockSAMgr_, GetSystemAbility(testing::_))
            .WillByDefault(Return(mockProxy_));
    }
};

void AnsNotificationResubscribeUnitTest::SetUpTestCase() {}

void AnsNotificationResubscribeUnitTest::TearDownTestCase() {}

void AnsNotificationResubscribeUnitTest::SetUp()
{
    if (!ans_) {
        ans_ = AnsNotification::GetInstance();
    }
    ++ans_->reSubscribeRetryEpoch_;
    ans_->reSubscribeRetryScheduled_.store(false);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ans_->subscriptionRecords_.clear();
        ans_->localLiveViewSubscriptionRecords_.clear();
        ans_->subscribers_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(ans_->badgeQueryMutex_);
        ans_->badgeQueryCallbacks_.clear();
    }
    mockProxy_ = sptr<MockAnsManagerProxy>(new MockAnsManagerProxy());
    mockSAMgr_ = sptr<MockSystemAbilityManager>(new MockSystemAbilityManager());
    ON_CALL(*mockSAMgr_, GetSystemAbility(testing::_))
        .WillByDefault(Return(nullptr));
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockSAMgr_;
}

void AnsNotificationResubscribeUnitTest::TearDown()
{
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = nullptr;
    mockSAMgr_ = nullptr;
    mockProxy_ = nullptr;
}

class ResubscribeTestSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override {}
    void OnDisconnected() override {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDied() override {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}
};

class ResubscribeLocalLiveViewSubscriber : public NotificationLocalLiveViewSubscriber {
public:
    void OnConnected() override {}
    void OnDisconnected() override {}
    void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override {}
    void OnDied() override {}
};

/*
 * @tc.name: ReSubscribeNotifications_0100
 * @tc.desc: ReSubscribeNotifications re-registers all shared_ptr style subscriptions
 *           after the ANS service restarts (design ADR-7, BR-12).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_0100, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber1 = std::make_shared<ResubscribeTestSubscriber>();
    auto subscriber2 = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(4).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber1), ERR_OK);
    EXPECT_EQ(ans_->SubscribeNotification(subscriber2), ERR_OK);
    ans_->ReSubscribeNotifications();
}

/*
 * @tc.name: ReSubscribeNotifications_0200
 * @tc.desc: ReSubscribeNotifications re-registers reference style subscriptions
 *           (SubscriberImpl path, NAPI/ArkTS chain) after the ANS service restarts.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_0200, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    ResubscribeTestSubscriber subscriber;
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ans_->ReSubscribeNotifications();
    EXPECT_CALL(*mockProxy_, Unsubscribe(_)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->UnSubscribeNotification(subscriber), ERR_OK);
}

/*
 * @tc.name: ReSubscribeNotifications_0300
 * @tc.desc: ReSubscribeNotifications keeps the original subscribeInfo filter
 *           (appNames) when re-registering a reference style subscription.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_0300, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    ResubscribeTestSubscriber subscriber;
    NotificationSubscribeInfo subscribeInfo;
    subscribeInfo.AddAppName("com.example.ans");
    sptr<NotificationSubscribeInfo> capturedInfo;
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _))
        .Times(2)
        .WillRepeatedly(DoAll(SaveArg<1>(&capturedInfo), Return(ERR_OK)));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber, subscribeInfo), ERR_OK);
    ASSERT_NE(capturedInfo, nullptr);
    EXPECT_EQ(capturedInfo->GetAppNames(), std::vector<std::string>({"com.example.ans"}));
    capturedInfo = nullptr;
    ans_->ReSubscribeNotifications();
    ASSERT_NE(capturedInfo, nullptr);
    EXPECT_EQ(capturedInfo->GetAppNames(), std::vector<std::string>({"com.example.ans"}));
    EXPECT_CALL(*mockProxy_, Unsubscribe(_, _)).WillOnce(Return(ERR_OK));
    NotificationSubscribeInfo unsubscribeInfo;
    unsubscribeInfo.AddAppName("com.example.ans");
    EXPECT_EQ(ans_->UnSubscribeNotification(subscriber, unsubscribeInfo), ERR_OK);
}

/*
 * @tc.name: ReSubscribeNotifications_0400
 * @tc.desc: ReSubscribeNotifications does not call the proxy when the
 *           subscription records are empty.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_0400, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(0);
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeSelf(_, _)).Times(0);
    ans_->ReSubscribeNotifications();
}

/*
 * @tc.name: OnAddSystemAbility_0100
 * @tc.desc: SaStatusChangeListener::OnAddSystemAbility triggers re-subscription only
 *           for SA 3203 (design ADR-7 trigger chain).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, OnAddSystemAbility_0100, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    AnsManagerDeathRecipient::SystemAbilityStatusChangeListener listener;
    listener.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "deviceId");
    listener.OnAddSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, "deviceId");
}

/*
 * @tc.name: SubscriptionRecord_NullParams_0100
 * @tc.desc: AddSubscriptionRecord/RemoveSubscriptionRecord ignore null stubs (defensive guard).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_NullParams_0100, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    clearLock.unlock();

    ans_->AddSubscriptionRecord(nullptr, nullptr, false, false, 0);
    ans_->RemoveSubscriptionRecord(nullptr);
    EXPECT_TRUE(ans_->subscriptionRecords_.empty());
}

/*
 * @tc.name: SubscriptionRecord_UpdateExisting_0200
 * @tc.desc: AddSubscriptionRecord updates the existing record (same stub) instead of appending a duplicate.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_UpdateExisting_0200, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: SubscriptionRecord_RemoveMissing_0300
 * @tc.desc: RemoveSubscriptionRecord keeps the records untouched when the stub has no record.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_RemoveMissing_0300, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    sptr<SubscriberListener> other =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(other, nullptr);
    ans_->RemoveSubscriptionRecord(other);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_ExpiredRecord_0500
 * @tc.desc: ReSubscribeNotifications drops records whose weak reference expired without touching the proxy.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_ExpiredRecord_0500,
    Function | MediumTest | Level1)
{
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ans_->subscriptionRecords_.clear();
        sptr<SubscriberListener> temp =
            new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
        ASSERT_NE(temp, nullptr);
        AnsNotification::SubscriptionRecord record;
        ans_->subscriptionRecords_.emplace_back(wptr<IAnsSubscriber>(temp), record);
        temp = nullptr;
    }

    SetMockProxy();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(0);
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _, _)).Times(0);
    EXPECT_CALL(*mockProxy_, SubscribeSelf(_, _)).Times(0);
    ans_->ReSubscribeNotifications();
    EXPECT_TRUE(ans_->subscriptionRecords_.empty());
}

/*
 * @tc.name: ReSubscribeNotifications_NullProxy_0600
 * @tc.desc: ReSubscribeNotifications keeps records when the ANS proxy is unavailable (service not yet ready).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_NullProxy_0600, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ON_CALL(*mockSAMgr_, GetSystemAbility(testing::_)).WillByDefault(Return(nullptr));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_V26_0700
 * @tc.desc: ReSubscribeNotifications re-registers a V26 subscription without subscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_V26_0700, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotificationV26(subscriber), ERR_OK);
    ans_->ReSubscribeNotifications();
}

/*
 * @tc.name: ReSubscribeNotifications_V26WithInfo_0800
 * @tc.desc: ReSubscribeNotifications re-registers a V26 subscription with its original subscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_V26WithInfo_0800, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(info, nullptr);
    info->AddAppName("com.example.ans");
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotificationV26(subscriber, info), ERR_OK);
    ans_->ReSubscribeNotifications();
}

/*
 * @tc.name: ReSubscribeNotifications_Self_0900
 * @tc.desc: ReSubscribeNotifications re-registers a self subscription through SubscribeSelf.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_Self_0900, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, SubscribeSelf(_, _)).Times(2).WillRepeatedly(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotificationSelf(subscriber), ERR_OK);
    ans_->ReSubscribeNotifications();
}

/*
 * @tc.name: UnSubscribeNotification_RetainRecord_1000
 * @tc.desc: A failed unsubscribe keeps the subscription record so that a later re-subscription can restore it.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_RetainRecord_1000, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    EXPECT_CALL(*mockProxy_, Unsubscribe(_)).WillOnce(Return(-1));
    EXPECT_NE(ans_->UnSubscribeNotification(subscriber), ERR_OK);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: UnSubscribeNotification_ReferenceRetain_1100
 * @tc.desc: Reference style unsubscribe failure keeps the subscription record (weak ref path).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_ReferenceRetain_1100,
    Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    ResubscribeTestSubscriber subscriber;
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    EXPECT_CALL(*mockProxy_, Unsubscribe(_)).WillOnce(Return(-1));
    EXPECT_NE(ans_->UnSubscribeNotification(subscriber), ERR_OK);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: UnSubscribeNotification_ReferenceInfoRetain_1200
 * @tc.desc: Reference style unsubscribe with subscribeInfo keeps the record when the proxy call fails.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_ReferenceInfoRetain_1200,
    Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    ResubscribeTestSubscriber subscriber;
    NotificationSubscribeInfo subscribeInfo;
    subscribeInfo.AddAppName("com.example.ans");
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeNotification(subscriber, subscribeInfo), ERR_OK);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    EXPECT_CALL(*mockProxy_, Unsubscribe(_, _)).WillOnce(Return(-1));
    EXPECT_NE(ans_->UnSubscribeNotification(subscriber, subscribeInfo), ERR_OK);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_DirectV26_1300
 * @tc.desc: A record forced to V26 without subscribeInfo is re-registered via SubscribeNotification(stub, flags).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_DirectV26_1300, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        ans_->subscriptionRecords_[0].second.isV26 = true;
    }
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_DirectV26WithInfo_1400
 * @tc.desc: A record forced to V26 with subscribeInfo is re-registered via SubscribeNotification(stub, info, flags).
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_DirectV26WithInfo_1400,
    Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(info, nullptr);
    info->AddAppName("com.example.ans");
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        ans_->subscriptionRecords_[0].second.isV26 = true;
        ans_->subscriptionRecords_[0].second.subscribeInfo = info;
    }
    EXPECT_CALL(*mockProxy_, SubscribeNotification(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_DirectSelf_1500
 * @tc.desc: A record forced to self takes the else-if branch and is re-registered through SubscribeSelf.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_DirectSelf_1500, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        ans_->subscriptionRecords_[0].second.isSelf = true;
    }
    EXPECT_CALL(*mockProxy_, SubscribeSelf(_, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_DirectPlain_1600
 * @tc.desc: A plain record without subscribeInfo takes the else branch and is re-registered through Subscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_DirectPlain_1600, Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        ans_->subscriptionRecords_[0].second.isV26 = false;
        ans_->subscriptionRecords_[0].second.isSelf = false;
        ans_->subscriptionRecords_[0].second.subscribeInfo = nullptr;
    }
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_DirectPlainWithInfo_1700
 * @tc.desc: A plain record with subscribeInfo takes the else branch with info and re-registers via Subscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_DirectPlainWithInfo_1700,
    Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(info, nullptr);
    info->AddAppName("com.example.ans");
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        ans_->subscriptionRecords_[0].second.isV26 = false;
        ans_->subscriptionRecords_[0].second.isSelf = false;
        ans_->subscriptionRecords_[0].second.subscribeInfo = info;
    }
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_ExpiredWithLive_1800
 * @tc.desc: Expired records are dropped while the live record in the same vector is still re-registered.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_ExpiredWithLive_1800,
    Function | MediumTest | Level1)
{
    std::unique_lock<std::mutex> clearLock(ans_->subscriberMutex_);
    ans_->subscriptionRecords_.clear();
    ans_->subscribers_.clear();
    clearLock.unlock();

    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        sptr<SubscriberListener> expired = new (std::nothrow)
            SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
        ASSERT_NE(expired, nullptr);
        AnsNotification::SubscriptionRecord record;
        ans_->subscriptionRecords_.emplace_back(wptr<IAnsSubscriber>(expired), record);
        expired = nullptr;
    }
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).Times(1).WillOnce(Return(ERR_OK));
    ans_->ReSubscribeNotifications();
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: UnSubscribeNotification_PartialFilter_1900
 * @tc.desc: A partial unsubscribe narrows the replay filter to the remaining bundle list,
 *           matching the server's partial-unsubscribe semantics.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_PartialFilter_1900, Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(info, nullptr);
    info->AddAppNames({"com.example.a", "com.example.b"});
    info->AddAppUid(1001);

    sptr<NotificationSubscribeInfo> capturedInfo;
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).Times(2)
        .WillRepeatedly(DoAll(SaveArg<1>(&capturedInfo), Return(ERR_OK)));
    EXPECT_CALL(*mockProxy_, Unsubscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber, info), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo->GetAppNames(),
            std::vector<std::string>({"com.example.a", "com.example.b"}));
    }

    sptr<NotificationSubscribeInfo> removedInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(removedInfo, nullptr);
    removedInfo->AddAppName("com.example.a");
    ASSERT_EQ(ans_->UnSubscribeNotification(subscriber, removedInfo), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        EXPECT_EQ(ans_->subscribers_.size(), 1);
        EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo->GetAppNames(),
            std::vector<std::string>({"com.example.b"}));
        EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo->GetAppUids(),
            std::vector<int32_t>({1001}));
    }

    capturedInfo = nullptr;
    ans_->ReSubscribeNotifications();
    ASSERT_NE(capturedInfo, nullptr);
    EXPECT_EQ(capturedInfo->GetAppNames(), std::vector<std::string>({"com.example.b"}));
    EXPECT_EQ(capturedInfo->GetAppUids(), std::vector<int32_t>({1001}));

    EXPECT_CALL(*mockProxy_, Unsubscribe(_)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->UnSubscribeNotification(subscriber), ERR_OK);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    EXPECT_TRUE(ans_->subscriptionRecords_.empty());
    EXPECT_TRUE(ans_->subscribers_.empty());
}

/*
 * @tc.name: UnSubscribeNotification_ReferencePartialFilter_2000
 * @tc.desc: The reference-style subscription path also preserves only the remaining
 *           filter after a partial unsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_ReferencePartialFilter_2000,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    ResubscribeTestSubscriber subscriber;
    NotificationSubscribeInfo info;
    info.AddAppNames({"com.example.a", "com.example.b"});

    sptr<NotificationSubscribeInfo> capturedInfo;
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).Times(2)
        .WillRepeatedly(DoAll(SaveArg<1>(&capturedInfo), Return(ERR_OK)));
    EXPECT_CALL(*mockProxy_, Unsubscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber, info), ERR_OK);

    NotificationSubscribeInfo removedInfo;
    removedInfo.AddAppName("com.example.a");
    ASSERT_EQ(ans_->UnSubscribeNotification(subscriber, removedInfo), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
        EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo->GetAppNames(),
            std::vector<std::string>({"com.example.b"}));
    }

    capturedInfo = nullptr;
    ans_->ReSubscribeNotifications();
    ASSERT_NE(capturedInfo, nullptr);
    EXPECT_EQ(capturedInfo->GetAppNames(), std::vector<std::string>({"com.example.b"}));
}

/*
 * @tc.name: ReSubscribeNotifications_LocalLiveView_2100
 * @tc.desc: LocalLiveView subscriptions are replayed after the ANS service restarts.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_LocalLiveView_2100,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    ResubscribeLocalLiveViewSubscriber subscriber;
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false)).Times(2).WillRepeatedly(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeLocalLiveViewNotification(subscriber, false), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    }
    ans_->ReSubscribeNotifications();
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        EXPECT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    }
}

/*
 * @tc.name: ReSubscribeNotifications_LocalLiveViewExpired_2200
 * @tc.desc: Expired LocalLiveView replay records are removed without invoking the proxy.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_LocalLiveViewExpired_2200,
    Function | MediumTest | Level1)
{
    {
        ResubscribeLocalLiveViewSubscriber subscriber;
        ans_->AddLocalLiveViewSubscriptionRecord(subscriber.impl_, true);
    }
    SetMockProxy();
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, _)).Times(0);
    ans_->ReSubscribeNotifications();
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        EXPECT_TRUE(ans_->localLiveViewSubscriptionRecords_.empty());
    }
}

/*
 * @tc.name: UnSubscribeNotification_RecordNotFound_2300
 * @tc.desc: A successful server unsubscribe with no local replay record removes the
 *           listener instead of leaving a zombie entry in subscribers_.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_RecordNotFound_2300,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->subscribers_.size(), 1);
        ans_->subscriptionRecords_.clear();
    }
    EXPECT_CALL(*mockProxy_, Unsubscribe(_)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->UnSubscribeNotification(subscriber), ERR_OK);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    EXPECT_TRUE(ans_->subscribers_.empty());
}

/*
 * @tc.name: LocalLiveView_PruneExpiredOnAdd_2400
 * @tc.desc: Adding a LocalLiveView replay record prunes expired weak entries immediately
 *           instead of retaining them until the ANS service restarts.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, LocalLiveView_PruneExpiredOnAdd_2400,
    Function | MediumTest | Level1)
{
    {
        ResubscribeLocalLiveViewSubscriber expired;
        ans_->AddLocalLiveViewSubscriptionRecord(expired.impl_, true);
    }
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    }

    ResubscribeLocalLiveViewSubscriber live;
    ans_->AddLocalLiveViewSubscriptionRecord(live.impl_, false);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    ASSERT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    sptr<IAnsSubscriberLocalLiveView> replayStub =
        ans_->localLiveViewSubscriptionRecords_[0].first.promote();
    ASSERT_NE(replayStub, nullptr);
    EXPECT_EQ(replayStub->AsObject(), live.impl_->AsObject());
    EXPECT_FALSE(ans_->localLiveViewSubscriptionRecords_[0].second.isNative);
}

/*
 * @tc.name: UnSubscribeNotification_PartialRemoveAll_2500
 * @tc.desc: Unsubscribing every filtered bundle removes the replay record and listener.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, UnSubscribeNotification_PartialRemoveAll_2500,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    sptr<NotificationSubscribeInfo> subscribeInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(subscribeInfo, nullptr);
    subscribeInfo->AddAppNames({"com.example.a", "com.example.b"});
    EXPECT_CALL(*mockProxy_, Subscribe(_, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*mockProxy_, Unsubscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber, subscribeInfo), ERR_OK);

    sptr<NotificationSubscribeInfo> removedInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(removedInfo, nullptr);
    removedInfo->AddAppNames({"com.example.a", "com.example.b"});
    ASSERT_EQ(ans_->UnSubscribeNotification(subscriber, removedInfo), ERR_OK);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    EXPECT_TRUE(ans_->subscriptionRecords_.empty());
    EXPECT_TRUE(ans_->subscribers_.empty());
}

/*
 * @tc.name: SubscriptionRecord_SubscribeAllPartial_2600
 * @tc.desc: A subscribe-all replay record keeps its original state when a partial
 *           unsubscribe cannot be represented by the server model.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_SubscribeAllPartial_2600,
    Function | MediumTest | Level1)
{
    sptr<SubscriberListener> listener =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(listener, nullptr);
    sptr<NotificationSubscribeInfo> subscribeAll = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(subscribeAll, nullptr);
    ans_->AddSubscriptionRecord(listener, subscribeAll, false, false, 0);

    sptr<NotificationSubscribeInfo> removedInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(removedInfo, nullptr);
    removedInfo->AddAppName("com.example.a");
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribe(listener, removedInfo),
        AnsNotification::ReplayRecordUpdateResult::KEPT);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo, subscribeAll);
}

/*
 * @tc.name: SubscriptionRecord_UidOnlyPartial_2700
 * @tc.desc: A uid-only replay filter is retained when the removed bundle name is not
 *           part of that filter.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_UidOnlyPartial_2700,
    Function | MediumTest | Level1)
{
    sptr<SubscriberListener> listener =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(listener, nullptr);
    sptr<NotificationSubscribeInfo> subscribeInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(subscribeInfo, nullptr);
    subscribeInfo->AddAppUid(1001);
    ans_->AddSubscriptionRecord(listener, subscribeInfo, false, false, 0);

    sptr<NotificationSubscribeInfo> removedInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(removedInfo, nullptr);
    removedInfo->AddAppName("com.example.a");
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribe(listener, removedInfo),
        AnsNotification::ReplayRecordUpdateResult::KEPT);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    EXPECT_EQ(ans_->subscriptionRecords_[0].second.subscribeInfo->GetAppUids(),
        std::vector<int32_t>({1001}));
}

/*
 * @tc.name: SubscriptionRecord_NullUpdate_2800
 * @tc.desc: Null stub updates and a missing listener entry take the defensive paths.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_NullUpdate_2800,
    Function | MediumTest | Level1)
{
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribe(nullptr, nullptr),
        AnsNotification::ReplayRecordUpdateResult::NOT_FOUND);
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribeLocked(nullptr, nullptr),
        AnsNotification::ReplayRecordUpdateResult::NOT_FOUND);

    sptr<SubscriberListener> listener =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(listener, nullptr);
    ans_->AddSubscriptionRecord(listener, nullptr, false, false, 0);
    ans_->UpdateSubscriberAfterUnsubscribeLocked(listener, nullptr);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    EXPECT_TRUE(ans_->subscriptionRecords_.empty());
}

/*
 * @tc.name: SubscriptionRecord_NoInfoPartial_2900
 * @tc.desc: A replay record without subscribeInfo is retained on a partial unsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_NoInfoPartial_2900,
    Function | MediumTest | Level1)
{
    sptr<SubscriberListener> listener =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(listener, nullptr);
    ans_->AddSubscriptionRecord(listener, nullptr, false, false, 0);
    sptr<NotificationSubscribeInfo> removedInfo = new (std::nothrow) NotificationSubscribeInfo();
    ASSERT_NE(removedInfo, nullptr);
    removedInfo->AddAppName("com.example.a");
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribe(listener, removedInfo),
        AnsNotification::ReplayRecordUpdateResult::KEPT);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    EXPECT_EQ(ans_->subscriptionRecords_.size(), 1);
}

/*
 * @tc.name: ReSubscribeNotifications_NormalErrorBranches_3000
 * @tc.desc: Replay distinguishes non-retryable and retryable normal subscription failures.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_NormalErrorBranches_3000,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_FALSE(ans_->ReSubscribeNotificationsInternal());
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_TRUE(ans_->ReSubscribeNotificationsInternal());
}

/*
 * @tc.name: ReSubscribeNotifications_LocalLiveErrorBranches_3100
 * @tc.desc: Replay distinguishes non-retryable and retryable LocalLiveView failures.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_LocalLiveErrorBranches_3100,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    ResubscribeLocalLiveViewSubscriber subscriber;
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeLocalLiveViewNotification(subscriber, false), ERR_OK);
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false))
        .WillOnce(Return(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_FALSE(ans_->ReSubscribeNotificationsInternal());
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false))
        .WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_TRUE(ans_->ReSubscribeNotificationsInternal());
}

/*
 * @tc.name: ReSubscribeNotifications_RetryAlreadyScheduled_3200
 * @tc.desc: A failed replay does not schedule twice when a retry is already active.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_RetryAlreadyScheduled_3200,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ans_->reSubscribeRetryScheduled_.store(true);
    ON_CALL(*mockSAMgr_, GetSystemAbility(testing::_)).WillByDefault(Return(nullptr));
    ans_->ReSubscribeNotifications();
    EXPECT_TRUE(ans_->reSubscribeRetryScheduled_.load());
    ans_->reSubscribeRetryScheduled_.store(false);
}

/*
 * @tc.name: LocalLiveView_NullAndUpdate_3300
 * @tc.desc: LocalLiveView replay records ignore null stubs and update existing entries.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, LocalLiveView_NullAndUpdate_3300,
    Function | MediumTest | Level1)
{
    ans_->AddLocalLiveViewSubscriptionRecord(nullptr, false);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        EXPECT_TRUE(ans_->localLiveViewSubscriptionRecords_.empty());
    }
    ResubscribeLocalLiveViewSubscriber subscriber;
    ans_->AddLocalLiveViewSubscriptionRecord(subscriber.impl_, true);
    ans_->AddLocalLiveViewSubscriptionRecord(subscriber.impl_, false);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    ASSERT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    EXPECT_FALSE(ans_->localLiveViewSubscriptionRecords_[0].second.isNative);
}

/*
 * @tc.name: ReSubscribeRetry_EpochAndEmpty_3400
 * @tc.desc: Retry handling respects epoch ownership and stops when no record needs replay.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeRetry_EpochAndEmpty_3400,
    Function | MediumTest | Level1)
{
    ans_->reSubscribeRetryEpoch_.store(2);
    ans_->reSubscribeRetryScheduled_.store(true);
    ans_->reSubscribeRetryScheduledEpoch_.store(3);
    EXPECT_FALSE(ans_->HandleReSubscribeRetry(1, 1));
    EXPECT_TRUE(ans_->reSubscribeRetryScheduled_.load());

    ans_->reSubscribeRetryScheduledEpoch_.store(1);
    EXPECT_FALSE(ans_->HandleReSubscribeRetry(1, 1));
    EXPECT_FALSE(ans_->reSubscribeRetryScheduled_.load());

    ans_->reSubscribeRetryScheduled_.store(true);
    EXPECT_FALSE(ans_->HandleReSubscribeRetry(1, 2));
    EXPECT_FALSE(ans_->reSubscribeRetryScheduled_.load());
}

/*
 * @tc.name: ReSubscribeRetry_AttemptLimit_3500
 * @tc.desc: Retry handling returns true below the limit and stops at the final attempt.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeRetry_AttemptLimit_3500,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    auto subscriber = std::make_shared<ResubscribeTestSubscriber>();
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->SubscribeNotification(subscriber), ERR_OK);
    ans_->reSubscribeRetryEpoch_.store(2);
    ans_->reSubscribeRetryScheduledEpoch_.store(2);
    ans_->reSubscribeRetryScheduled_.store(true);
    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_TRUE(ans_->HandleReSubscribeRetry(1, 2));
    EXPECT_TRUE(ans_->reSubscribeRetryScheduled_.load());

    EXPECT_CALL(*mockProxy_, Subscribe(_, _)).WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_FALSE(ans_->HandleReSubscribeRetry(4, 2));
    EXPECT_FALSE(ans_->reSubscribeRetryScheduled_.load());
}

/*
 * @tc.name: SubscriptionRecord_UpdateSecondEntry_3600
 * @tc.desc: Replay record update skips unrelated listeners and removes only the matched one.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscriptionRecord_UpdateSecondEntry_3600,
    Function | MediumTest | Level1)
{
    sptr<SubscriberListener> first =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    sptr<SubscriberListener> second =
        new (std::nothrow) SubscriberListener(std::make_shared<ResubscribeTestSubscriber>());
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ans_->AddSubscriptionRecord(first, nullptr, false, false, 0);
    ans_->AddSubscriptionRecord(second, nullptr, false, false, 0);
    EXPECT_EQ(ans_->UpdateSubscriptionRecordAfterUnsubscribe(second, nullptr),
        AnsNotification::ReplayRecordUpdateResult::REMOVED);
    std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
    ASSERT_EQ(ans_->subscriptionRecords_.size(), 1);
    sptr<IAnsSubscriber> remaining = ans_->subscriptionRecords_[0].first.promote();
    ASSERT_NE(remaining, nullptr);
    EXPECT_EQ(remaining->AsObject(), first->AsObject());
}

class ResubscribeBadgeQueryCallback : public IBadgeQueryCallback {
public:
    ErrCode OnBadgeNumberQuery(const sptr<NotificationBundleOption> &bundleOption, int32_t &badgeNumber) override
    {
        badgeNumber = 0;
        return ERR_OK;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/*
 * @tc.name: ReSubscribeNotifications_BadgeQueryCallback_4400
 * @tc.desc: A registered badge query callback is replayed after an ANS restart, even for a
 *           badge-only client with no notification subscriptions.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_BadgeQueryCallback_4400,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    {
        std::lock_guard<std::mutex> lock(ans_->badgeQueryMutex_);
        ans_->badgeQueryCallbacks_.clear();
    }
    auto callback = std::make_shared<ResubscribeBadgeQueryCallback>();
    EXPECT_CALL(*mockProxy_, RegisterBadgeQueryCallback(_)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->RegisterBadgeQueryCallback(callback), ERR_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->badgeQueryMutex_);
        ASSERT_EQ(ans_->badgeQueryCallbacks_.size(), 1);
    }
    EXPECT_CALL(*mockProxy_, RegisterBadgeQueryCallback(_)).WillOnce(Return(ERR_OK));
    EXPECT_FALSE(ans_->ReSubscribeNotificationsInternal());
}

/*
 * @tc.name: ReSubscribeNotifications_BadgeQueryCallbackRetry_4500
 * @tc.desc: A retryable badge query callback replay failure requests a retry.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeNotifications_BadgeQueryCallbackRetry_4500,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    {
        std::lock_guard<std::mutex> lock(ans_->badgeQueryMutex_);
        ans_->badgeQueryCallbacks_.clear();
    }
    auto callback = std::make_shared<ResubscribeBadgeQueryCallback>();
    EXPECT_CALL(*mockProxy_, RegisterBadgeQueryCallback(_)).WillOnce(Return(ERR_OK));
    ASSERT_EQ(ans_->RegisterBadgeQueryCallback(callback), ERR_OK);
    EXPECT_CALL(*mockProxy_, RegisterBadgeQueryCallback(_))
        .WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_TRUE(ans_->ReSubscribeNotificationsInternal());
}

/*
 * @tc.name: ReSubscribeRetry_DelaySequence_4600
 * @tc.desc: Retry backoff grows exponentially (500/1000/2000/4000 ms) and is capped.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeRetry_DelaySequence_4600,
    Function | MediumTest | Level1)
{
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(0), 0);
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(1), 500);
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(2), 1000);
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(3), 2000);
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(4), 4000);
    EXPECT_EQ(AnsNotification::GetReSubscribeRetryDelayMs(5), 4000);
}

/*
 * @tc.name: ReSubscribeRetry_InvalidatedByServiceDied_4700
 * @tc.desc: Service death bumps the retry epoch and releases the scheduled slot, so a stale
 *           retry chain can neither survive nor block the recovery of the next service start.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, ReSubscribeRetry_InvalidatedByServiceDied_4700,
    Function | MediumTest | Level1)
{
    const uint64_t staleEpoch = ans_->reSubscribeRetryEpoch_.load();
    ans_->reSubscribeRetryScheduled_.store(true);
    ans_->reSubscribeRetryScheduledEpoch_.store(staleEpoch);

    ans_->OnServiceDied();
    EXPECT_EQ(ans_->reSubscribeRetryEpoch_.load(), staleEpoch + 1);
    EXPECT_FALSE(ans_->reSubscribeRetryScheduled_.load());

    ans_->reSubscribeRetryScheduled_.store(true);
    ans_->reSubscribeRetryScheduledEpoch_.store(staleEpoch + 1);
    ans_->ScheduleReSubscribeRetry(2, staleEpoch);
    EXPECT_EQ(ans_->reSubscribeRetryScheduledEpoch_.load(), staleEpoch + 1);
    EXPECT_FALSE(ans_->HandleReSubscribeRetry(1, staleEpoch));
    EXPECT_TRUE(ans_->reSubscribeRetryScheduled_.load());

    EXPECT_FALSE(ans_->HandleReSubscribeRetry(1, staleEpoch + 1));
    EXPECT_FALSE(ans_->reSubscribeRetryScheduled_.load());
}

/*
 * @tc.name: SubscribeLocalLiveView_RecordOnlyOnSuccess_4800
 * @tc.desc: A failed LocalLiveView subscribe leaves no replay record behind, otherwise the
 *           never-accepted subscription would be replayed on every ANS restart.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationResubscribeUnitTest, SubscribeLocalLiveView_RecordOnlyOnSuccess_4800,
    Function | MediumTest | Level1)
{
    SetMockProxy();
    ResubscribeLocalLiveViewSubscriber subscriber;
    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false))
        .WillOnce(Return(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_EQ(ans_->SubscribeLocalLiveViewNotification(subscriber, false), ERR_ANS_INNER_SERVICE_NOT_CONNECTED);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        EXPECT_TRUE(ans_->localLiveViewSubscriptionRecords_.empty());
    }

    EXPECT_CALL(*mockProxy_, SubscribeLocalLiveView(_, false)).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ans_->SubscribeLocalLiveViewNotification(subscriber, false), ERR_ANS_INNER_OK);
    {
        std::lock_guard<std::mutex> lock(ans_->subscriberMutex_);
        ASSERT_EQ(ans_->localLiveViewSubscriptionRecords_.size(), 1);
    }
}
}  // namespace Notification
}  // namespace OHOS
