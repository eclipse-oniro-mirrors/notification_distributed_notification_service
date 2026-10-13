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

#include <gtest/gtest.h>

#include "ans_inner_errors.h"
#define private public // NOLINT
#define protected public // NOLINT
#include "notification_subscriber_manager.h"
#undef private
#undef protected
#include "ans_subscriber_stub.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class NotificationSubscriberDispatchBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

class FakeAnsSubscriber : public AnsSubscriberStub {
public:
    int consumedWithMap = 0;
    int consumedWithoutMap = 0;
    int consumedListWithMap = 0;
    int consumedListWithoutMap = 0;
    int canceledWithMap = 0;
    int canceledWithoutMap = 0;
    int canceledListWithMap = 0;
    int canceledListWithoutMap = 0;

    ErrCode OnConnected() override { return ERR_OK; }
    ErrCode OnDisconnected() override { return ERR_OK; }
    ErrCode OnConsumed(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap) override
    {
        consumedWithMap++;
        return ERR_OK;
    }
    ErrCode OnConsumed(const sptr<Notification> &notification) override
    {
        consumedWithoutMap++;
        return ERR_OK;
    }
    ErrCode OnConsumedList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap) override
    {
        consumedListWithMap++;
        return ERR_OK;
    }
    ErrCode OnConsumedList(const std::vector<sptr<Notification>> &notifications) override
    {
        consumedListWithoutMap++;
        return ERR_OK;
    }
    ErrCode OnCanceled(const sptr<Notification> &notification,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override
    {
        canceledWithMap++;
        return ERR_OK;
    }
    ErrCode OnCanceled(const sptr<Notification> &notification, int32_t deleteReason) override
    {
        canceledWithoutMap++;
        return ERR_OK;
    }
    ErrCode OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override
    {
        canceledListWithMap++;
        return ERR_OK;
    }
    ErrCode OnCanceledList(const std::vector<sptr<Notification>> &notifications, int32_t deleteReason) override
    {
        canceledListWithoutMap++;
        return ERR_OK;
    }
    ErrCode OnSystemUpdate(const sptr<Notification> &notification) override { return ERR_OK; }
    ErrCode OnEnabledPriorityChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnEnabledPriorityByBundleChanged(
        const sptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnEnabledWatchStatusChanged(uint32_t watchStatus) override { return ERR_OK; }
    ErrCode OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override { return ERR_OK; }
    ErrCode OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override { return ERR_OK; }
    ErrCode OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnEnabledSilentReminderChanged(const sptr<EnabledSilentReminderCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnNotificationSwitchChanged(const sptr<NotificationSwitchChangedCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override { return ERR_OK; }
    ErrCode OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {
        return ERR_OK;
    }
    ErrCode OnApplicationInfoNeedChanged(
        const sptr<NotificationApplicationChangeInfo> &applicationChangeInfo) override
    {
        return ERR_OK;
    }
    ErrCode OnOperationResponse(const sptr<NotificationOperationInfo> &operationInfo, int32_t &funcResult) override
    {
        return ERR_OK;
    }
};

/**
 * @tc.number    : DispatchOnConsumed_00100
 * @tc.name      : DispatchOnConsumed
 * @tc.desc      : test DispatchOnConsumed without sorting map invokes OnConsumed without map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnConsumed_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    manager->DispatchOnConsumed(record, notification, nullptr);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->consumedWithoutMap, 1);
    EXPECT_EQ(fake->consumedWithMap, 0);
}

/**
 * @tc.number    : DispatchOnConsumed_00200
 * @tc.name      : DispatchOnConsumed
 * @tc.desc      : test DispatchOnConsumed with sorting map invokes OnConsumed with map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnConsumed_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    manager->DispatchOnConsumed(record, notification, notificationMap);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->consumedWithMap, 1);
    EXPECT_EQ(fake->consumedWithoutMap, 0);
}

/**
 * @tc.number    : DispatchOnCanceled_00100
 * @tc.name      : DispatchOnCanceled
 * @tc.desc      : test DispatchOnCanceled without sorting map invokes OnCanceled without map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnCanceled_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    manager->DispatchOnCanceled(record, notification, nullptr, 0);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->canceledWithoutMap, 1);
    EXPECT_EQ(fake->canceledWithMap, 0);
}

/**
 * @tc.number    : DispatchOnCanceled_00200
 * @tc.name      : DispatchOnCanceled
 * @tc.desc      : test DispatchOnCanceled with sorting map invokes OnCanceled with map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnCanceled_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    manager->DispatchOnCanceled(record, notification, notificationMap, 0);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->canceledWithMap, 1);
    EXPECT_EQ(fake->canceledWithoutMap, 0);
}

/**
 * @tc.number    : DispatchOnConsumedList_00100
 * @tc.name      : DispatchOnConsumedList
 * @tc.desc      : test DispatchOnConsumedList without sorting map invokes OnConsumedList without map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnConsumedList_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    std::vector<sptr<Notification>> notifications = {notification};
    manager->DispatchOnConsumedList(record, notifications, nullptr);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->consumedListWithoutMap, 1);
    EXPECT_EQ(fake->consumedListWithMap, 0);
}

/**
 * @tc.number    : DispatchOnConsumedList_00200
 * @tc.name      : DispatchOnConsumedList
 * @tc.desc      : test DispatchOnConsumedList with sorting map invokes OnConsumedList with map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnConsumedList_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    std::vector<sptr<Notification>> notifications = {notification};
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    manager->DispatchOnConsumedList(record, notifications, notificationMap);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->consumedListWithMap, 1);
    EXPECT_EQ(fake->consumedListWithoutMap, 0);
}

/**
 * @tc.number    : DispatchOnCanceledList_00100
 * @tc.name      : DispatchOnCanceledList
 * @tc.desc      : test DispatchOnCanceledList without sorting map invokes OnCanceledList without map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnCanceledList_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    std::vector<sptr<Notification>> notifications = {notification};
    manager->DispatchOnCanceledList(record, notifications, nullptr, 0);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->canceledListWithoutMap, 1);
    EXPECT_EQ(fake->canceledListWithMap, 0);
}

/**
 * @tc.number    : DispatchOnCanceledList_00200
 * @tc.name      : DispatchOnCanceledList
 * @tc.desc      : test DispatchOnCanceledList with sorting map invokes OnCanceledList with map
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, DispatchOnCanceledList_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscriber = new FakeAnsSubscriber();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    std::vector<sptr<Notification>> notifications = {notification};
    sptr<NotificationSortingMap> notificationMap = new NotificationSortingMap();
    manager->DispatchOnCanceledList(record, notifications, notificationMap, 0);
    auto *fake = static_cast<FakeAnsSubscriber *>(record->subscriber.GetRefPtr());
    ASSERT_NE(fake, nullptr);
    EXPECT_EQ(fake->canceledListWithMap, 1);
    EXPECT_EQ(fake->canceledListWithoutMap, 0);
}

/**
 * @tc.number    : ReportNotificationsRemovedEvent_00100
 * @tc.name      : ReportNotificationsRemovedEvent
 * @tc.desc      : test ReportNotificationsRemovedEvent with empty and non-empty inputs
 */
HWTEST_F(NotificationSubscriberDispatchBranchTest, ReportNotificationsRemovedEvent_00100,
    Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    manager->ReportNotificationsRemovedEvent({});
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    manager->ReportNotificationsRemovedEvent({notification});
    EXPECT_NE(notification, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
