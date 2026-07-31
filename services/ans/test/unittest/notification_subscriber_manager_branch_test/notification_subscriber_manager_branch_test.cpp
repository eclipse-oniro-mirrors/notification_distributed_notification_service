/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_ut_constant.h"
#define private public
#define protected public
#include "ans_result_data_synchronizer.h"
#include "advanced_notification_service.h"
#include "notification_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"
#include "notification_subscriber_manager.h"
#include "notification_request.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "mock_ipc_skeleton.h"

extern void MockGetUserId(bool mockRet);
extern void MockGetBundleName(bool mockRet);
extern void MockGetNotificationSlotRet(bool mockRet);
extern void MockGetEnabledForBundleSlotsRet(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);
extern void MockDeleteKvFromDb(int32_t mockRet);

using namespace OHOS::Security::AccessToken;
using namespace testing::ext;
namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class NotificationSubscriberManagerBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : NotifyRefreshPriority_00100
 * @tc.name      : NotifyRefreshPriority_00100
 * @tc.desc      : test NotifyRefreshPriority_00100 function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotifyRefreshPriority_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    std::vector<sptr<NotificationRequest>> requests;
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    ASSERT_NE(nullptr, notificationSubscriberManager);
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyRefreshPrioritySwitch(requests, priorityEnable);
    notificationSubscriberManager->NotifyRefreshPriorityIntelligent(true, requests);
    notificationSubscriberManager->NotifyRefreshPriorityStrategy(requests, strategies);
    notificationSubscriberManager->NotifyRefreshPriorityConfig(requests);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00100
 * @tc.name      : MatchPriorityTypeToBits_00100
 * @tc.desc      : test MatchPriorityTypeToBits with PARAM_IN
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN));
    EXPECT_EQ(result, NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT |
        NotificationConstant::PriorityStrategyStatus::STATUS_APPLICATION_DEFINED);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00200
 * @tc.name      : MatchPriorityTypeToBits_00200
 * @tc.desc      : test MatchPriorityTypeToBits with KEYWORD
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD));
    EXPECT_EQ(result, NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT |
        NotificationConstant::PriorityStrategyStatus::STATUS_USER_DEFINED);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00300
 * @tc.name      : MatchPriorityTypeToBits_00300
 * @tc.desc      : test MatchPriorityTypeToBits with AI
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_EQ(result, NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT |
        NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00400
 * @tc.name      : MatchPriorityTypeToBits_00400
 * @tc.desc      : test MatchPriorityTypeToBits with PUSH_RULE
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00400, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE));
    EXPECT_EQ(result, NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT |
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_RULE);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00500
 * @tc.name      : MatchPriorityTypeToBits_00500
 * @tc.desc      : test MatchPriorityTypeToBits with invalid type returns 0
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00500, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(static_cast<int32_t>(99));
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number    : MatchPriorityStrategy_00100
 * @tc.name      : MatchPriorityStrategy_00100
 * @tc.desc      : test MatchPriorityStrategy STATUS_SYSTEM_DEFAULT matches PARAM_IN
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00200
 * @tc.name      : MatchPriorityStrategy_00200
 * @tc.desc      : test MatchPriorityStrategy STATUS_INTELLIGENT matches AI
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00300
 * @tc.name      : MatchPriorityStrategy_00300
 * @tc.desc      : test MatchPriorityStrategy STATUS_INTELLIGENT does not match KEYWORD
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD));
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00400
 * @tc.name      : MatchPriorityStrategy_00400
 * @tc.desc      : test MatchPriorityStrategy with strategy 0 returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00400, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(0,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00500
 * @tc.name      : MatchPriorityStrategy_00500
 * @tc.desc      : test MatchPriorityStrategy combined strategy matches AI
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00500, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    int32_t combinedStrategy = NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT |
        NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT;
    auto result = manager->MatchPriorityStrategy(combinedStrategy,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00100
 * @tc.name      : IsSubscribedByPriority_00100
 * @tc.desc      : test IsSubscribedByPriority with null notification returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT;
    sptr<Notification> notification = nullptr;
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00200
 * @tc.name      : IsSubscribedByPriority_00200
 * @tc.desc      : test IsSubscribedByPriority with no extendInfo returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT;
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetNotificationId(0);
    req->SetCreatorBundleName("testBundle");
    sptr<Notification> notification = new Notification(req);
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00300
 * @tc.name      : IsSubscribedByPriority_00300
 * @tc.desc      : test IsSubscribedByPriority with null request returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    sptr<Notification> notification = new Notification();
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00400
 * @tc.name      : IsSubscribedByPriority_00400
 * @tc.desc      : test IsSubscribedByPriority with strategy 0 returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00400, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = 0;
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : GetBundlePriorityStrategy_00100
 * @tc.name      : GetBundlePriorityStrategy_00100
 * @tc.desc      : test GetBundlePriorityStrategy returns 0 with no priority subscribers
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, GetBundlePriorityStrategy_00100,
    Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    sptr<Notification> notification = new Notification(req);
    auto result = manager->GetBundlePriorityStrategy(notification);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number    : MatchPriorityStrategy_00600
 * @tc.name      : MatchPriorityStrategy_00600
 * @tc.desc      : test MatchPriorityStrategy STATUS_SYSTEM_RULE matches PUSH_RULE
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00600, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_RULE,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00700
 * @tc.name      : MatchPriorityStrategy_00700
 * @tc.desc      : test MatchPriorityStrategy STATUS_USER_DEFINED matches KEYWORD
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00700, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_USER_DEFINED,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00800
 * @tc.name      : MatchPriorityStrategy_00800
 * @tc.desc      : test MatchPriorityStrategy STATUS_APPLICATION_DEFINED matches PARAM_IN
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00800, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_APPLICATION_DEFINED,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_00900
 * @tc.name      : MatchPriorityStrategy_00900
 * @tc.desc      : test MatchPriorityStrategy STATUS_SYSTEM_DEFAULT matches KEYWORD
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_00900, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_01000
 * @tc.name      : MatchPriorityStrategy_01000
 * @tc.desc      : test MatchPriorityStrategy STATUS_SYSTEM_DEFAULT matches AI
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_01000, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityStrategy_01100
 * @tc.name      : MatchPriorityStrategy_01100
 * @tc.desc      : test MatchPriorityStrategy STATUS_SYSTEM_DEFAULT matches PUSH_RULE
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityStrategy_01100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityStrategy(
        NotificationConstant::PriorityStrategyStatus::STATUS_SYSTEM_DEFAULT,
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE));
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : MatchPriorityTypeToBits_00600
 * @tc.name      : MatchPriorityTypeToBits_00600
 * @tc.desc      : test MatchPriorityTypeToBits with invalid type returns 0
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, MatchPriorityTypeToBits_00600, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto result = manager->MatchPriorityTypeToBits(static_cast<int32_t>(-1));
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number    : AddConsumedHashCodes_00100
 * @tc.name      : AddConsumedHashCodes_00100
 * @tc.desc      : test AddConsumedHashCodes adds hashCode and HasConsumedHashCode returns true
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AddConsumedHashCodes_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    EXPECT_TRUE(manager->HasConsumedHashCode(req->GetNotificationHashCode()));
}

/**
 * @tc.number    : AddConsumedHashCodes_00200
 * @tc.name      : AddConsumedHashCodes_00200
 * @tc.desc      : test AddConsumedHashCodes with nullptr notification skipped
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AddConsumedHashCodes_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<Notification> nullNotification = nullptr;
    manager->AddConsumedHashCodes({nullNotification});
    EXPECT_TRUE(manager->consumedHashCodes_.empty());
}

/**
 * @tc.number    : AddConsumedHashCodes_00300
 * @tc.name      : AddConsumedHashCodes_00300
 * @tc.desc      : test AddConsumedHashCodes deduplicates same hashCode
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AddConsumedHashCodes_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification, notification});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 1);
}

/**
 * @tc.number    : AddConsumedHashCodes_00400
 * @tc.name      : AddConsumedHashCodes_00400
 * @tc.desc      : test AddConsumedHashCodes with multiple different notifications
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AddConsumedHashCodes_00400, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req1 = new NotificationRequest();
    req1->SetNotificationId(1);
    req1->SetCreatorBundleName("bundle1");
    req1->SetCreatorUid(100);
    req1->SetOwnerBundleName("owner1");
    sptr<NotificationRequest> req2 = new NotificationRequest();
    req2->SetNotificationId(2);
    req2->SetCreatorBundleName("bundle2");
    req2->SetCreatorUid(200);
    req2->SetOwnerBundleName("owner2");
    sptr<Notification> notification1 = new Notification(req1);
    sptr<Notification> notification2 = new Notification(req2);
    manager->AddConsumedHashCodes({notification1, notification2});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 2);
    EXPECT_TRUE(manager->HasConsumedHashCode(req1->GetNotificationHashCode()));
    EXPECT_TRUE(manager->HasConsumedHashCode(req2->GetNotificationHashCode()));
}

/**
 * @tc.number    : HasConsumedHashCode_00100
 * @tc.name      : HasConsumedHashCode_00100
 * @tc.desc      : test HasConsumedHashCode returns false when hashCode not in set
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, HasConsumedHashCode_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    EXPECT_FALSE(manager->HasConsumedHashCode("nonexistent_hash"));
}

/**
 * @tc.number    : RemoveConsumedHashCodes_00100
 * @tc.name      : RemoveConsumedHashCodes_00100
 * @tc.desc      : test RemoveConsumedHashCodes removes hashCode and HasConsumedHashCode returns false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, RemoveConsumedHashCodes_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    EXPECT_TRUE(manager->HasConsumedHashCode(req->GetNotificationHashCode()));
    manager->RemoveConsumedHashCodes({notification});
    EXPECT_FALSE(manager->HasConsumedHashCode(req->GetNotificationHashCode()));
}

/**
 * @tc.number    : RemoveConsumedHashCodes_00200
 * @tc.name      : RemoveConsumedHashCodes_00200
 * @tc.desc      : test RemoveConsumedHashCodes with nullptr notification skipped
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, RemoveConsumedHashCodes_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 1);
    sptr<Notification> nullNotification = nullptr;
    manager->RemoveConsumedHashCodes({nullNotification});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 1);
}

/**
 * @tc.number    : RemoveConsumedHashCodes_00300
 * @tc.name      : RemoveConsumedHashCodes_00300
 * @tc.desc      : test RemoveConsumedHashCodes removes only specified hashCode, others remain
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, RemoveConsumedHashCodes_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req1 = new NotificationRequest();
    req1->SetNotificationId(1);
    req1->SetCreatorBundleName("bundle1");
    req1->SetCreatorUid(100);
    req1->SetOwnerBundleName("owner1");
    sptr<NotificationRequest> req2 = new NotificationRequest();
    req2->SetNotificationId(2);
    req2->SetCreatorBundleName("bundle2");
    req2->SetCreatorUid(200);
    req2->SetOwnerBundleName("owner2");
    sptr<Notification> notification1 = new Notification(req1);
    sptr<Notification> notification2 = new Notification(req2);
    manager->AddConsumedHashCodes({notification1, notification2});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 2);
    manager->RemoveConsumedHashCodes({notification1});
    EXPECT_EQ(manager->consumedHashCodes_.size(), 1);
    EXPECT_FALSE(manager->HasConsumedHashCode(req1->GetNotificationHashCode()));
    EXPECT_TRUE(manager->HasConsumedHashCode(req2->GetNotificationHashCode()));
}

/**
 * @tc.number    : ConsumedHashCodesCapacity_00100
 * @tc.name      : ConsumedHashCodesCapacity_00100
 * @tc.desc      : test consumedHashCodes list capacity limit evicts oldest entry via pop_front
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ConsumedHashCodesCapacity_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    std::string firstHashCode;
    for (int32_t i = 0; i <= static_cast<int32_t>(NotificationSubscriberManager::MAX_CONSUMED_HASH_CODE_LIST_SIZE);
         i++) {
        sptr<NotificationRequest> req = new NotificationRequest();
        req->SetNotificationId(i);
        req->SetCreatorBundleName("bundle" + std::to_string(i));
        req->SetCreatorUid(i + 100);
        req->SetOwnerBundleName("owner" + std::to_string(i));
        sptr<Notification> notification = new Notification(req);
        if (i == 0) {
            firstHashCode = req->GetNotificationHashCode();
        }
        manager->AddConsumedHashCodes({notification});
    }
    EXPECT_EQ(manager->consumedHashCodes_.size(),
        NotificationSubscriberManager::MAX_CONSUMED_HASH_CODE_LIST_SIZE);
    EXPECT_FALSE(manager->HasConsumedHashCode(firstHashCode));
    EXPECT_EQ(manager->consumedHashCodes_.front(), "1_bundle1_101_owner1");
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00100
 * @tc.name      : ShouldNotifyPrioritySubscribers_00100
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns false when notification is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_FALSE(manager->ShouldNotifyPrioritySubscribers(record, nullptr));
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00200
 * @tc.name      : ShouldNotifyPrioritySubscribers_00200
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns false when request is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = nullptr;
    sptr<Notification> notification = new Notification(req);
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_FALSE(manager->ShouldNotifyPrioritySubscribers(record, notification));
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00300
 * @tc.name      : ShouldNotifyPrioritySubscribers_00300
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns false when userId does not match
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    req->SetReceiverUserId(200);
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_FALSE(manager->ShouldNotifyPrioritySubscribers(record, notification));
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00400
 * @tc.name      : ShouldNotifyPrioritySubscribers_00400
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns false when distributed collaborate
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00400, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    req->SetReceiverUserId(100);
    req->SetDistributedCollaborate(true);
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_FALSE(manager->ShouldNotifyPrioritySubscribers(record, notification));
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00500
 * @tc.name      : ShouldNotifyPrioritySubscribers_00500
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns false when not consumed
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00500, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    req->SetReceiverUserId(100);
    sptr<Notification> notification = new Notification(req);
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_FALSE(manager->ShouldNotifyPrioritySubscribers(record, notification));
}

/**
 * @tc.number    : ShouldNotifyPrioritySubscribers_00600
 * @tc.name      : ShouldNotifyPrioritySubscribers_00600
 * @tc.desc      : test ShouldNotifyPrioritySubscribers returns true when all conditions satisfied
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ShouldNotifyPrioritySubscribers_00600, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    req->SetReceiverUserId(100);
    sptr<Notification> notification = new Notification(req);
    manager->AddConsumedHashCodes({notification});
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->userId = 100;
    EXPECT_TRUE(manager->ShouldNotifyPrioritySubscribers(record, notification));
}

/**
 * @tc.number    : NotificationSubscriberManager_00100
 * @tc.name      : NotificationSubscriberManager_00100
 * @tc.desc      : test NotifyConsumed function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyConsumed(notification, notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00200
 * @tc.name      : NotificationSubscriberManager_00200
 * @tc.desc      : test NotifyCanceled function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00200, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyCanceled(notification, notificationMap, deleteReason);
}

/**
 * @tc.number    : NotificationSubscriberManager_00300
 * @tc.name      : NotificationSubscriberManager_00300
 * @tc.desc      : test NotifyUpdated function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00300, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyUpdated(notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00400
 * @tc.name      : NotificationSubscriberManager_00400
 * @tc.desc      : test NotifyDoNotDisturbDateChanged function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00400, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    int32_t uid = 200200;
    notificationSubscriberManager->NotifyDoNotDisturbDateChanged(0, date, uid);
}

/**
 * @tc.number    : NotificationSubscriberManager_00500
 * @tc.name      : NotificationSubscriberManager_00500
 * @tc.desc      : test NotifyEnabledNotificationChanged function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00500, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<EnabledNotificationCallbackData> callbackData = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyEnabledNotificationChanged(callbackData);
}

/**
 * @tc.number    : NotificationSubscriberManager_00600
 * @tc.name      : NotificationSubscriberManager_00600
 * @tc.desc      : test OnRemoteDied function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00600, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    wptr<IRemoteObject> object = nullptr;
    notificationSubscriberManager->OnRemoteDied(object);
}

/**
 * @tc.number    : NotificationSubscriberManager_00800
 * @tc.name      : NotificationSubscriberManager_00800
 * @tc.desc      : test RemoveSubscriberInner function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00800, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<IAnsSubscriber> subscriber = nullptr;
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    ASSERT_EQ(ERR_ANS_INNER_INVALID_PARAM,
        notificationSubscriberManager.RemoveSubscriberInner(subscriber, subscribeInfo));
}
#ifdef ANM_SUPPORT_DUMP
/**
 * @tc.number  : AdvancedNotificationService_00200
 * @tc.name    : AdvancedNotificationService_00200
 * @tc.desc    : test ActiveNotificationDump function and userId != SUBSCRIBE_USER_INIT
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00200, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00300
 * @tc.name    : AdvancedNotificationService_00300
 * @tc.desc    : test ActiveNotificationDump function and bundle != record->notification->GetBundleName().
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00300, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
/**
 * @tc.number  : AdvancedNotificationService_00400
 * @tc.name    : AdvancedNotificationService_00400
 * @tc.desc    : test ActiveNotificationDump function and record->deviceId is not empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00400, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    record->deviceId = "<deviceId>";
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00500
 * @tc.name    : AdvancedNotificationService_00500
 * @tc.desc    : test ActiveNotificationDump function and record->request->GetOwnerUid() > 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00500, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = 1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "";
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00600
 * @tc.name    : AdvancedNotificationService_00600
 * @tc.desc    : test ActiveNotificationDump function and record->request->GetOwnerUid() < 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00600, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = -1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "";
    advancedNotificationService.notificationList_.push_back(record);
    std::shared_ptr<NotificationRecord> record1 = std::make_shared<NotificationRecord>();
    record1->notification = new Notification();
    record1->request = new NotificationRequest();
    record1->request->SetOwnerUid(uid);
    record1->request->SetReceiverUserId(0);
    advancedNotificationService.notificationList_.push_back(record1);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00700
 * @tc.name    : AdvancedNotificationService_00700
 * @tc.desc    : test DistributedNotificationDump function and record->notification == nullptr.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00700, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = nullptr;
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01300
 * @tc.name    : AdvancedNotificationService_01300
 * @tc.desc    : test DistributedNotificationDump function and recvUserId != record->notification->GetRecvUserId().
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01300, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    record->request->SetReceiverUserId(2);
    MockGetUserId(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00800
 * @tc.name    : AdvancedNotificationService_00800
 * @tc.desc    : test DistributedNotificationDump function and userId != SUBSCRIBE_USER_INIT.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00800, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    MockGetUserId(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00900
 * @tc.name    : AdvancedNotificationService_00900
 * @tc.desc    : test DistributedNotificationDump function and bundle is not empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00900, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01000
 * @tc.name    : AdvancedNotificationService_01000
 * @tc.desc    : test DistributedNotificationDump function and record->deviceId is empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01000, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->deviceId = "";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01100
 * @tc.name    : AdvancedNotificationService_01100
 * @tc.desc    : test DistributedNotificationDump function and record->request->GetOwnerUid() > 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01100, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = 1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "<deviceId>";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01200
 * @tc.name    : AdvancedNotificationService_01200
 * @tc.desc    : test DistributedNotificationDump function and record->request->GetOwnerUid() < 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01200, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = -1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "<deviceId>";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}
#endif

/**
 * @tc.number  : ActiveNotificationDump_0009
 * @tc.name    : ActiveNotificationDump
 * @tc.desc    : test ActiveNotificationDump function and record->notification == nullptr.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ActiveNotificationDump_0009, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new (std::nothrow) Notification();
    record->request = nullptr;
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}
#endif

/**
 * @tc.number  : AdvancedNotificationService_01400
 * @tc.name    : AdvancedNotificationService_01400
 * @tc.desc    : Test PrepareNotificationRequest function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01400, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    bool isAgentTrue = true;
    req->SetIsAgentNotification(isAgentTrue);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.PrepareNotificationRequest(req).GetErrCode(),
        (int)ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_01500
 * @tc.name    : AdvancedNotificationService_01500
 * @tc.desc    : Test CancelAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01500, Function | SmallTest | Level1)
{
    int32_t notificationId = 1;
    std::string representativeBundle = "<representativeBundle>";
    int32_t userId = 2;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    InnerErrorCode result = ERR_ANS_INNER_NON_SYSTEM_APP;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService.CancelAsBundle(notificationId, representativeBundle, userId,
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number  : AdvancedNotificationService_11500
 * @tc.name    : AdvancedNotificationService_11500
 * @tc.desc    : Test CancelAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_11500, Function | SmallTest | Level1)
{
    int32_t notificationId = 1;
    std::string representativeBundle = "<representativeBundle>";
    int32_t userId = 2;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.CancelAsBundle(notificationId, representativeBundle, userId),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01600
 * @tc.name    : AdvancedNotificationService_01600
 * @tc.desc    : Test AddSlots function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01600, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.AddSlots(slots), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01700
 * @tc.name    : AdvancedNotificationService_01700
 * @tc.desc    : Test Delete function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01700, Function | SmallTest | Level1)
{
    std::string key = "<key>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.Delete(key, removeReason), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01800
 * @tc.name    : AdvancedNotificationService_01800
 * @tc.desc    : Test DeleteByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =  new NotificationBundleOption();

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.DeleteByBundle(bundleOption), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01900
 * @tc.name    : AdvancedNotificationService_01900
 * @tc.desc    : Test DeleteAll function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01900, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.DeleteAll(), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02000
 * @tc.name    : AdvancedNotificationService_02000
 * @tc.desc    : Test GetSlotsByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02000, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotsByBundle(bundleOption, slots), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02100
 * @tc.name    : AdvancedNotificationService_02100
 * @tc.desc    : Test UpdateSlots function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02100, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.UpdateSlots(bundleOption, slots), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02200
 * @tc.name    : AdvancedNotificationService_02200
 * @tc.desc    : Test SetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02200, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02300
 * @tc.name    : AdvancedNotificationService_02300
 * @tc.desc    : Test GetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02300, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    InnerErrorCode result = ERR_ANS_INNER_NON_SYSTEM_APP;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption,
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number  : AdvancedNotificationService_023001
 * @tc.name    : AdvancedNotificationService_023001
 * @tc.desc    : Test GetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_023001, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02400
 * @tc.name    : AdvancedNotificationService_02400
 * @tc.desc    : Test Unsubscribe function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02400, Function | SmallTest | Level1)
{
    sptr<IAnsSubscriber> subscriber = nullptr;
    sptr<NotificationSubscribeInfo> info = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.Unsubscribe(subscriber, info), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02500
 * @tc.name    : AdvancedNotificationService_02500
 * @tc.desc    : Test GetAllActiveNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02500, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetAllActiveNotifications(notifications), ERR_ANS_INNER_NON_SYSTEM_APP);
    InnerErrorCode result = ERR_ANS_INNER_NON_SYSTEM_APP;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService.GetAllActiveNotifications(
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number  : AdvancedNotificationService_02600
 * @tc.name    : AdvancedNotificationService_02600
 * @tc.desc    : Test GetSpecialActiveNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02600, Function | SmallTest | Level1)
{
    std::vector<std::string> key;
    std::vector<sptr<Notification>> notifications;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.GetSpecialActiveNotifications(key, notifications), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02700
 * @tc.name    : AdvancedNotificationService_02700
 * @tc.desc    : Test SetNotificationsEnabledForAllBundles function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02700, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForAllBundles(deviceId, enabled),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02800
 * @tc.name    : AdvancedNotificationService_02800
 * @tc.desc    : Test SetNotificationsEnabledForAllBundles function and GetActiveUserId is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02800, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    bool enabled = true;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockQueryForgroundOsAccountId(false, 1);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForAllBundles(deviceId, enabled),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_02900
 * @tc.name    : AdvancedNotificationService_02900
 * @tc.desc    : Test SetNotificationsEnabledForSpecialBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02900, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForSpecialBundle(deviceId, bundleOption, enabled),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03000
 * @tc.name    : AdvancedNotificationService_03000
 * @tc.desc    : Test IsAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03000, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsAllowedNotify(enabled), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03100
 * @tc.name    : AdvancedNotificationService_03100
 * @tc.desc    : Test IsAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03100, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockQueryForgroundOsAccountId(false, 1);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsAllowedNotify(enabled), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_03200
 * @tc.name    : AdvancedNotificationService_03200
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03300
 * @tc.name    : AdvancedNotificationService_03300
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and targetBundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed), ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03400
 * @tc.name    : AdvancedNotificationService_03400
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and GetActiveUserId is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    MockQueryForgroundOsAccountId(false, 1);
    bool allowed = true;

    int32_t uid = 2;
    bundleOption->SetUid(uid);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_03500
 * @tc.name    : AdvancedNotificationService_03500
 * @tc.desc    : Test RemoveNotification function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t notificationId = 1;
    std::string label = "<label>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveNotification(bundleOption, notificationId, label, removeReason),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03600
 * @tc.name    : AdvancedNotificationService_03600
 * @tc.desc    : Test RemoveNotification function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03600, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t notificationId = 0;
    std::string label = "<label>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveNotification(bundleOption, notificationId, label, removeReason),
        ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03700
 * @tc.name    : AdvancedNotificationService_03700
 * @tc.desc    : Test RemoveAllNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveAllNotifications(bundleOption), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03800
 * @tc.name    : AdvancedNotificationService_03800
 * @tc.desc    : Test RemoveAllNotifications function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveAllNotifications(bundleOption), ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03900
 * @tc.name    : AdvancedNotificationService_03900
 * @tc.desc    : Test GetSlotNumAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03900, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint64_t num = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotNumAsBundle(bundleOption, num), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_04000
 * @tc.name    : AdvancedNotificationService_04000
 * @tc.desc    : Test GetSlotNumAsBundle function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    uint64_t num = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotNumAsBundle(bundleOption, num), ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_04100
 * @tc.name    : AdvancedNotificationService_04100
 * @tc.desc    : Test RemoveGroupByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string groupName = "<groupName>";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_04200
 * @tc.name    : AdvancedNotificationService_04200
 * @tc.desc    : Test RemoveGroupByBundle function and groupName is empty
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string groupName = "";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number  : AdvancedNotificationService_04300
 * @tc.name    : AdvancedNotificationService_04300
 * @tc.desc    : Test RemoveGroupByBundle function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::string groupName = "<groupName>";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_04900
 * @tc.name    : AdvancedNotificationService_04900
 * @tc.desc    : Test EnableDistributed function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04900, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.EnableDistributed(enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_05000
 * @tc.name    : AdvancedNotificationService_05000
 * @tc.desc    : Test EnableDistributedByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_05100
 * @tc.name    : AdvancedNotificationService_05100
 * @tc.desc    : Test EnableDistributedByBundle function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_05200
 * @tc.name    : AdvancedNotificationService_05200
 * @tc.desc    : Test IsDistributedEnableByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_05300
 * @tc.name    : AdvancedNotificationService_05300
 * @tc.desc    : Test IsDistributedEnableByBundle function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_05400
 * @tc.name    : AdvancedNotificationService_05400
 * @tc.desc    : Test GetDeviceRemindType function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05400, Function | SmallTest | Level1)
{
    int32_t remindType = -1;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetDeviceRemindType(remindType), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05500
 * @tc.name    : AdvancedNotificationService_05500
 * @tc.desc    : Test IsSpecialUserAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05500, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsSpecialUserAllowedNotify(userId, allowed), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05600
 * @tc.name    : AdvancedNotificationService_05600
 * @tc.desc    : Test SetNotificationsEnabledByUser function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05600, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledByUser(userId, allowed), ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05900
 * @tc.name    : AdvancedNotificationService_05900
 * @tc.desc    : Test SetEnabledForBundleSlot function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05900, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;
    bool isForceControl = false;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06000
 * @tc.name    : AdvancedNotificationService_06000
 * @tc.desc    : Test SetEnabledForBundleSlot function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;
    bool isForceControl = false;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl),
        ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06100
 * @tc.name    : AdvancedNotificationService_06100
 * @tc.desc    : Test GetEnabledForBundleSlot function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06200
 * @tc.name    : AdvancedNotificationService_06200
 * @tc.desc    : Test GetEnabledForBundleSlot function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06300
 * @tc.name    : AdvancedNotificationService_06300
 * @tc.desc    : Test GetEnabledForBundleSlot function and DB query failed
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 1;
    bundleOption->SetUid(notificationId);
    MockGetEnabledForBundleSlotsRet(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INNER_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_06400
 * @tc.name    : AdvancedNotificationService_06400
 * @tc.desc    : Test GetEnabledForBundleSlot function and slot not found in DB
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 1;
    bundleOption->SetUid(notificationId);
    MockGetEnabledForBundleSlotsRet(true);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number  : AdvancedNotificationService_06500
 * @tc.name    : AdvancedNotificationService_06500
 * @tc.desc    : Test SetSyncNotificationEnabledWithoutApp function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06500, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.SetSyncNotificationEnabledWithoutApp(userId, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_06600
 * @tc.name    : AdvancedNotificationService_06600
 * @tc.desc    : Test GetSyncNotificationEnabledWithoutApp function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06600, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    int32_t ret = advancedNotificationService.GetSyncNotificationEnabledWithoutApp(userId, enabled);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
#else
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_OPERATION);
#endif
}

/**
 * @tc.number  : AdvancedNotificationService_06700
 * @tc.name    : AdvancedNotificationService_06700
 * @tc.desc    : Test GetEnabledForBundleSlotSelf function and slot == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetNotificationSlotRet(true);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_NE(advancedNotificationService.GetEnabledForBundleSlotSelf(slotType, enabled), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_06800
 * @tc.name    : AdvancedNotificationService_06800
 * @tc.desc    : Test GetEnabledForBundleSlotSelf function and GetNotificationSlot false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06800, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetNotificationSlotRet(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlotSelf(slotType, enabled), ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06900
 * @tc.name    : AdvancedNotificationService_06900
 * @tc.desc    : Test IsNeedSilentInDoNotDisturbMode function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06900, Function | SmallTest | Level1)
{
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_07000
 * @tc.name    : AdvancedNotificationService_07000
 * @tc.desc    : Test SetGeofenceEnabled function and result == ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07000, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    AdvancedNotificationService advancedNotificationService;
    auto result = advancedNotificationService.SetGeofenceEnabled(true);
    EXPECT_EQ(result, ERR_OK);
    result = advancedNotificationService.SetGeofenceEnabled(false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_07100
 * @tc.name    : AdvancedNotificationService_07100
 * @tc.desc    : Test OnNotifyDelayedNotificationInner function and result != ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07100, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = nullptr;
    EXPECT_EQ(advancedNotificationService.OnNotifyDelayedNotificationInner(parameter, nullptr),
        ERR_ANS_INNER_INVALID_PARAM);
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    ASSERT_NE(req, nullptr);
    parameter.request = req;
    req->notificationTrigger_ = nullptr;
    auto result = advancedNotificationService.OnNotifyDelayedNotificationInner(parameter, nullptr);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number  : AdvancedNotificationService_07200
 * @tc.name    : AdvancedNotificationService_07200
 * @tc.desc    : Test ClearDelayNotification function  and result == ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07200, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    std::vector<std::string> triggerKeys;
    triggerKeys.push_back("testKey");
    std::vector<int32_t> userIds;
    userIds.push_back(100);
    auto result =advancedNotificationService.ClearDelayNotification(triggerKeys, userIds);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_07300
 * @tc.name    : AdvancedNotificationService_07300
 * @tc.desc    : Test ClearDelayNotification function and ERR_ANS_INNER_INVALID_PARAM == ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07300, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    int32_t userId = 100;
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    ASSERT_NE(req, nullptr);
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    ASSERT_NE(notification, nullptr);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    ASSERT_NE(record, nullptr);
    record->notification = notification;
    req->SetDistributedCollaborate(true);
    req->SetDistributedHashCode("hashCodeTest");
    record->request = req;
    advancedNotificationService.triggerNotificationList_.push_back(record);
    MockDeleteKvFromDb(ERR_ANS_INNER_SERVICE_NOT_READY);
    auto result = advancedNotificationService.PublishDelayedNotification(triggerKey, userId);
    EXPECT_EQ(result, ERR_ANS_INNER_SERVICE_NOT_READY);
    MockDeleteKvFromDb(ERR_OK);
    result = advancedNotificationService.PublishDelayedNotification(triggerKey, userId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_07400
 * @tc.name    : AdvancedNotificationService_07400
 * @tc.desc    : Test GetDelayedNotificationParameterByTriggerKey function  and result == ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07400, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    int32_t userId = 100;
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    ASSERT_NE(req, nullptr);
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    ASSERT_NE(notification, nullptr);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    ASSERT_NE(record, nullptr);
    record->notification = notification;
    req->SetDistributedCollaborate(true);
    req->SetDistributedHashCode("hashCodeTest");
    record->request = req;
    record->request->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    advancedNotificationService.triggerNotificationList_.push_back(record);
    auto result = advancedNotificationService.GetDelayedNotificationParameterByTriggerKey(
        triggerKey, parameter, record);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_07500
 * @tc.name    : AdvancedNotificationService_07500
 * @tc.desc    : Test UpdateTriggerRequest function
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07500, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    ASSERT_NE(request, nullptr);
    request->SetDeliveryTime(0);
    request->notificationContentType_ = NotificationContent::Type::LOCAL_LIVE_VIEW;
    request1 = nullptr;
    advancedNotificationService.UpdateTriggerRequest(request1);
    advancedNotificationService.UpdateTriggerRequest(request);
    EXPECT_EQ(request->GetDeliveryTime(), 0);
    request->SetContent(nullptr);
    request->notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    request->slotType_ = NotificationConstant::SlotType::LIVE_VIEW;
    advancedNotificationService.UpdateTriggerRequest(request);
    EXPECT_EQ(request->GetDeliveryTime(), 0);
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    ASSERT_NE(mediaContent, nullptr);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(mediaContent);
    ASSERT_NE(content, nullptr);
    request->SetContent(content);
    request->notificationTrigger_ = nullptr;
    request->notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    request->slotType_ = NotificationConstant::SlotType::LIVE_VIEW;
    advancedNotificationService.UpdateTriggerRequest(request);
    EXPECT_NE(request->GetDeliveryTime(), 0);
    content->content_ = nullptr;
    request->SetContent(content);
    request->SetDeliveryTime(0);
    request->notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    request->slotType_ = NotificationConstant::SlotType::LIVE_VIEW;
    advancedNotificationService.UpdateTriggerRequest(request);
    EXPECT_EQ(request->GetDeliveryTime(), 0);
}

/**
 * @tc.number  : AdvancedNotificationService_07600
 * @tc.name    : AdvancedNotificationService_07600
 * @tc.desc    : Test ParseGeofenceNotificationFromDb functionand result == ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07600, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    std::string value = R"({
        "id": 1001,
        "name": "test_geo_fence",
        "triggerTokenCaller": 0,
        "triggerUid": 0,
        "isSystemApp": true
    })";
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    auto result = advancedNotificationService.ParseGeofenceNotificationFromDb(value, requestDb);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(requestDb.isSystemApp);
}

/**
 * @tc.number  : AdvancedNotificationService_07700
 * @tc.name    : AdvancedNotificationService_07700
 * @tc.desc    : Test SetTriggerNotificationRequestToDb function
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_07700, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    ASSERT_NE(request, nullptr);
    request->ownerUid_ = 1;
    requestDb.request = request;
    std::shared_ptr<NotificationLiveViewContent> notificationLiveViewContent =
        std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(notificationLiveViewContent, nullptr);
    notificationLiveViewContent->SetIsOnlyLocalUpdate(true);
    notificationLiveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> notificationContent = std::make_shared<NotificationContent>();
    ASSERT_NE(notificationContent, nullptr);
    notificationContent->content_ = notificationLiveViewContent;
    requestDb.request->notificationContent_ = notificationContent;
    requestDb.request->SetAutoDeletedTime(1);
    requestDb.request->slotType_ = NotificationConstant::SlotType::LIVE_VIEW;
    requestDb.request->notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    auto result = advancedNotificationService.SetTriggerNotificationRequestToDb(requestDb);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : ClearLiveViewContent_00100
 * @tc.name      : ClearLiveViewContent
 * @tc.desc      : test ClearLiveViewContent with nullptr notification
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ClearLiveViewContent_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<Notification> notification = nullptr;
    manager->ClearLiveViewContent(notification);
    EXPECT_EQ(notification, nullptr);
}

/**
 * @tc.number    : ClearLiveViewContent_00200
 * @tc.name      : ClearLiveViewContent
 * @tc.desc      : test ClearLiveViewContent with CommonLiveView notification clears picture map
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ClearLiveViewContent_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    PictureMap pictureMap;
    pictureMap["key"] = { std::make_shared<Media::PixelMap>() };
    liveViewContent->SetPicture(pictureMap);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    req->SetContent(content);
    sptr<Notification> notification = new Notification(req);
    auto beforeContent = notification->GetNotificationRequest().GetContent();
    auto beforeLiveView = std::static_pointer_cast<NotificationLiveViewContent>(
        beforeContent->GetNotificationContent());
    EXPECT_FALSE(beforeLiveView->GetPicture().empty());
    manager->ClearLiveViewContent(notification);
    auto afterContent = notification->GetNotificationRequest().GetContent();
    auto afterLiveView = std::static_pointer_cast<NotificationLiveViewContent>(
        afterContent->GetNotificationContent());
    EXPECT_TRUE(afterLiveView->GetPicture().empty());
}

/**
 * @tc.number    : ClearLiveViewContent_00300
 * @tc.name      : ClearLiveViewContent
 * @tc.desc      : test ClearLiveViewContent with SystemLiveView notification clears button and capsule icon
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, ClearLiveViewContent_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto icon = std::make_shared<Media::PixelMap>();
    NotificationCapsule capsule;
    capsule.SetIcon(icon);
    localLiveViewContent->SetCapsule(capsule);
    EXPECT_NE(localLiveViewContent->GetCapsule().GetIcon(), nullptr);
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    req->SetContent(content);
    sptr<Notification> notification = new Notification(req);
    manager->ClearLiveViewContent(notification);
    auto afterContent = notification->GetNotificationRequest().GetContent();
    auto afterLocalLiveView = std::static_pointer_cast<NotificationLocalLiveViewContent>(
        afterContent->GetNotificationContent());
    EXPECT_EQ(afterLocalLiveView->GetCapsule().GetIcon(), nullptr);
    EXPECT_TRUE(afterLocalLiveView->GetButton().GetAllButtonIcons().empty());
}

/**
 * @tc.number    : GetBundlePriorityStrategy_00200
 * @tc.name      : GetBundlePriorityStrategy
 * @tc.desc      : test GetBundlePriorityStrategy with priority subscriber but null request
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, GetBundlePriorityStrategy_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    manager->subscriberRecordList_.push_back(record);
    sptr<Notification> notification = new Notification();
    auto result = manager->GetBundlePriorityStrategy(notification);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.number    : IsSubscribedByPriority_00500
 * @tc.name      : IsSubscribedByPriority
 * @tc.desc      : test IsSubscribedByPriority returns false when userId does not match
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00500, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    record->userId = 100;
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetReceiverUserId(200);
    sptr<Notification> notification = new Notification(req);
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00600
 * @tc.name      : IsSubscribedByPriority
 * @tc.desc      : test IsSubscribedByPriority returns false when distributed collaborate
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00600, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    record->userId = 100;
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetReceiverUserId(100);
    req->SetDistributedCollaborate(true);
    sptr<Notification> notification = new Notification(req);
    int64_t bundlePriorityStrategy = 0;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsSubscribedByPriority_00700
 * @tc.name      : IsSubscribedByPriority
 * @tc.desc      : test IsSubscribedByPriority returns true when STATUS_ALL_PRIORITY matches bundlePriorityStrategy
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, IsSubscribedByPriority_00700, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    record->userId = 100;
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetReceiverUserId(100);
    sptr<Notification> notification = new Notification(req);
    int64_t bundlePriorityStrategy = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    auto result = manager->IsSubscribedByPriority(record, notification, bundlePriorityStrategy);
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : NotifyConsumedSubscribers_00100
 * @tc.name      : NotifyConsumedSubscribers
 * @tc.desc      : test NotifyConsumedSubscribers with null notification returns early
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotifyConsumedSubscribers_00100, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    manager->NotifyConsumedSubscribers(notification, notificationMap, 0);
    EXPECT_EQ(notification, nullptr);
}

/**
 * @tc.number    : NotifyConsumedSubscribers_00200
 * @tc.name      : NotifyConsumedSubscribers
 * @tc.desc      : test NotifyConsumedSubscribers with null request returns early
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotifyConsumedSubscribers_00200, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<Notification> notification = new Notification();
    sptr<NotificationSortingMap> notificationMap = nullptr;
    manager->NotifyConsumedSubscribers(notification, notificationMap, 0);
    EXPECT_NE(notification, nullptr);
}

/**
 * @tc.number    : NotifyConsumedSubscribers_00300
 * @tc.name      : NotifyConsumedSubscribers
 * @tc.desc      : test NotifyConsumedSubscribers skips priority subscriber when ShouldNotifyPrioritySubscribers false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotifyConsumedSubscribers_00300, Function | SmallTest | Level1)
{
    auto manager = std::make_shared<NotificationSubscriberManager>();
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetCreatorBundleName("test.bundle");
    req->SetCreatorUid(100);
    req->SetOwnerBundleName("test.owner");
    req->SetReceiverUserId(100);
    sptr<Notification> notification = new Notification(req);
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->priorityStrategy_ = NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY;
    record->userId = 100;
    manager->subscriberRecordList_.push_back(record);
    sptr<NotificationSortingMap> notificationMap = nullptr;
    manager->NotifyConsumedSubscribers(notification, notificationMap, 0);
    EXPECT_FALSE(manager->HasConsumedHashCode(
        notification->GetNotificationRequestPoint()->GetNotificationHashCode()));
}

/**
 * @tc.name: RemoveSubscriberInner_NullRecipient_00001
 * @tc.desc: Test RemoveSubscriberInner when recipient_ is nullptr (no crash)
 * @tc.type: FUNC
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, RemoveSubscriberInner_NullRecipient_00001,
    Function | SmallTest | Level1)
{
    NotificationSubscriberManager::GetInstance()->recipient_ = nullptr;
    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(nullptr, nullptr);
    EXPECT_EQ(NotificationSubscriberManager::GetInstance()->recipient_, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
