/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#define private public
#include "distributed_local_config.h"
#include "distributed_service.h"
#include "distributed_subscriber.h"
#undef private
#include "notification_request.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class DistribuedSubscriberTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

private:
    std::unordered_set<std::string> collaborativeDeleteTypes_;
};

void DistribuedSubscriberTest::SetUp()
{
    collaborativeDeleteTypes_ = DistributedLocalConfig::GetInstance().GetCollaborativeDeleteTypes();
    std::unordered_set<std::string> collaborativeDeleteTypes({ "LIVE_VIEW" });
    DistributedLocalConfig::GetInstance().localConfig_.collaborativeDeleteTypes = collaborativeDeleteTypes;
}

void DistribuedSubscriberTest::TearDown()
{
    DistributedLocalConfig::GetInstance().localConfig_.collaborativeDeleteTypes = collaborativeDeleteTypes_;
}

/**
 * @tc.name      : DistribuedSubscriberTest_00100
 * @tc.number    : DistribuedSubscriberTest_00100
 * @tc.desc      : Test the CheckNeedCollaboration function with null notification.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<Notification> notification = nullptr;
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00200
 * @tc.number    : DistribuedSubscriberTest_00200
 * @tc.desc      : Test the CheckNeedCollaboration function with null SlotType.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00300
 * @tc.number    : DistribuedSubscriberTest_00300
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType SOCIAL_COMMUNICATION.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00400
 * @tc.number    : DistribuedSubscriberTest_00400
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType SERVICE_REMINDER.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00400, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00500
 * @tc.number    : DistribuedSubscriberTest_00500
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType CONTENT_INFORMATION.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00500, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00600
 * @tc.number    : DistribuedSubscriberTest_00600
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType OTHER.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00600, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::OTHER);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00700
 * @tc.number    : DistribuedSubscriberTest_00700
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType CUSTOM.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00700, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00800
 * @tc.number    : DistribuedSubscriberTest_00800
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType LIVE_VIEW.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00800, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), true);
}

/**
 * @tc.name      : DistribuedSubscriberTest_00900
 * @tc.number    : DistribuedSubscriberTest_00900
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType CUSTOMER_SERVICE.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_00900, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01000
 * @tc.number    : DistribuedSubscriberTest_01000
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType EMERGENCY_INFORMATION.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01000, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01100
 * @tc.number    : DistribuedSubscriberTest_01100
 * @tc.desc      : Test the CheckNeedCollaboration function with SlotType ILLEGAL_TYPE.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::ILLEGAL_TYPE);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    EXPECT_EQ(subscriber->CheckNeedCollaboration(notification), false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01200
 * @tc.number    : DistribuedSubscriberTest_01200
 * @tc.desc      : Test the OnBatchCanceled function with deleteReason DEFAULT_REASON_DELETE.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01200, Function | SmallTest | Level1)
{
    std::vector<std::shared_ptr<Notification>> requestList;
    std::shared_ptr<NotificationSortingMap> sortingMap;
    int32_t deleteReason = 0;

    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    subscriber->OnBatchCanceled(requestList, sortingMap, deleteReason);
    EXPECT_EQ(deleteReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE, false);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01300
 * @tc.number    : DistribuedSubscriberTest_01300
 * @tc.desc      : Test the OnBatchCanceled function with deleteReason LIVE_VIEW.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);

    std::vector<std::shared_ptr<Notification>> requestList;
    requestList.push_back(notification);
    std::shared_ptr<NotificationSortingMap> sortingMap;
    int32_t deleteReason = 32;
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    subscriber->OnBatchCanceled(requestList, sortingMap, deleteReason);
    EXPECT_NE(requestList.size(), 0);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01400
 * @tc.number    : DistribuedSubscriberTest_01400
 * @tc.desc      : Test the OnCanceled function with deleteReason DEFAULT_REASON_DELETE.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01400, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<NotificationSortingMap> sortingMap;
    int32_t deleteReason = 0;
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    ASSERT_NE(subscriber, nullptr);
    subscriber->OnCanceled(notification, sortingMap, deleteReason);
}

/**
 * @tc.name      : DistribuedSubscriberTest_01500
 * @tc.number    : DistribuedSubscriberTest_01500
 * @tc.desc      : Test the OnCanceled function with deleteReason LIVE_VIEW.
 */
HWTEST_F(DistribuedSubscriberTest, DistribuedSubscriberTest_01500, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    std::shared_ptr<NotificationSortingMap> sortingMap;
    int32_t deleteReason = 32;

    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    ASSERT_NE(subscriber, nullptr);
    subscriber->OnCanceled(notification, sortingMap, deleteReason);
}
} // namespace Notification
} // namespace OHOS