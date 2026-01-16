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

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"

#define private public
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_result_data_synchronizer.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "int_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t LIST_SIZE_ONE = 1;
constexpr int32_t LIST_SIZE_THREE = 3;
constexpr int32_t LIST_SIZE_FOUR = 4;
constexpr int32_t LIST_SIZE_FIVE = 5;
constexpr int32_t LIST_SIZE_SIX = 6;
constexpr int32_t TEST_VALID_ID = 100;
constexpr int32_t TEST_INVALID_ID = 500;
}
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

class AnsGeofenceServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsGeofenceServiceTest::advancedNotificationService_ = nullptr;

void AnsGeofenceServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsGeofenceServiceTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_001
 * @tc.name      : Remove notifications from trigger notification list.
 * @tc.desc      : Test RemoveAllNotificationsByBundleNameFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->bundleOption = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record2->bundleOption->SetBundleName("testBundleName");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record3->bundleOption->SetBundleName("invalidBundleName");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FOUR);

    advancedNotificationService_->RemoveAllNotificationsByBundleNameFromTriggerNotificationList("testBundleName");
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_THREE);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_002
 * @tc.name      : Remove from trigger notification list.
 * @tc.desc      : Test RemoveFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->notification = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->request = sptr<NotificationRequest>::MakeSptr();
    record2->notification = sptr<Notification>::MakeSptr(record2->request);
    record2->notification->SetKey("testKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->request = sptr<NotificationRequest>::MakeSptr();
    record3->notification = sptr<Notification>::MakeSptr(record3->request);
    record3->notification->SetKey("invalidKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FOUR);

    advancedNotificationService_->RemoveFromTriggerNotificationList("testKey");
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_THREE);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_003
 * @tc.name      : Remove for delete all from trigger notificationList.
 * @tc.desc      : Test RemoveForDeleteAllFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_003, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->notification = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->request = sptr<NotificationRequest>::MakeSptr();
    record2->request->SetCreatorUserId(TEST_VALID_ID);
    record2->notification = sptr<Notification>::MakeSptr(record2->request);
    record2->notification->SetKey("testKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->request = sptr<NotificationRequest>::MakeSptr();
    record3->request->SetCreatorUserId(TEST_INVALID_ID);
    record3->notification = sptr<Notification>::MakeSptr(record3->request);
    record3->notification->SetKey("testKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);

    auto record4 = std::make_shared<NotificationRecord>();
    record4->request = sptr<NotificationRequest>::MakeSptr();
    record4->request->SetCreatorUserId(TEST_INVALID_ID);
    record4->notification = sptr<Notification>::MakeSptr(record4->request);
    record4->notification->SetKey("invalidKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record4);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FIVE);

    advancedNotificationService_->RemoveForDeleteAllFromTriggerNotificationList("testKey", TEST_VALID_ID);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FOUR);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_004
 * @tc.name      : Cancel continuous task notification from trigger notification list.
 * @tc.desc      : Test CancelContinuousTaskNotificationFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_004, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->bundleOption = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record2->bundleOption->SetBundleName("testBundleName");
    record2->notification = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record3->bundleOption->SetBundleName("testBundleName");
    record3->request = sptr<NotificationRequest>::MakeSptr();
    record3->request->SetCreatorUserId(TEST_VALID_ID);
    record3->notification = sptr<Notification>::MakeSptr(record3->request);
    record3->notification->SetKey("testKey");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);

    auto record4 = std::make_shared<NotificationRecord>();
    record4->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record4->bundleOption->SetBundleName("");
    record4->bundleOption->SetUid(TEST_VALID_ID);
    record4->request = sptr<NotificationRequest>::MakeSptr();
    record4->request->SetCreatorUserId(TEST_VALID_ID);
    record4->request->SetNotificationId(TEST_VALID_ID);
    record4->request->SetLabel("testLabel");
    record4->notification = sptr<Notification>::MakeSptr(record4->request);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record4);

    auto record5 = std::make_shared<NotificationRecord>();
    record5->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record5->bundleOption->SetBundleName("invalidBundleName");
    record5->bundleOption->SetUid(TEST_INVALID_ID);
    record5->request = sptr<NotificationRequest>::MakeSptr();
    record5->request->SetCreatorUserId(TEST_INVALID_ID);
    record5->request->SetNotificationId(TEST_INVALID_ID);
    record5->request->SetLabel("invalidLabel");
    record5->notification = sptr<Notification>::MakeSptr(record5->request);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record5);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_SIX);
    advancedNotificationService_->CancelContinuousTaskNotificationFromTriggerNotificationList("testLabel",
        TEST_VALID_ID, TEST_VALID_ID);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FIVE);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_005
 * @tc.name      : Get record from trigger notificationList.
 * @tc.desc      : Test GetRecordFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_005, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->bundleOption = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record2->bundleOption->SetBundleName("testBundleName");
    record2->notification = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record3->bundleOption->SetBundleName("");
    record3->bundleOption->SetUid(TEST_VALID_ID);
    record3->request = sptr<NotificationRequest>::MakeSptr();
    record3->request->SetNotificationId(TEST_VALID_ID);
    record3->request->SetLabel("testLabel");
    record3->request->SetReceiverUserId(TEST_VALID_ID);
    record3->notification = sptr<Notification>::MakeSptr(record3->request);
    record3->bundleOption->SetUid(TEST_VALID_ID);
    record3->bundleOption->SetBundleName("testBundleName");
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);

    auto record4 = std::make_shared<NotificationRecord>();
    record4->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record4->bundleOption->SetBundleName("invalidBundleName");
    record4->bundleOption->SetUid(TEST_INVALID_ID);
    record4->request = sptr<NotificationRequest>::MakeSptr();
    record4->request->SetNotificationId(TEST_INVALID_ID);
    record4->request->SetLabel("invalidLabel");
    record4->request->SetReceiverUserId(TEST_INVALID_ID);
    record4->notification = sptr<Notification>::MakeSptr(record4->request);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record4);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FIVE);
    AdvancedNotificationService::GetRecordParameter parameter{
        .notificationId = TEST_VALID_ID,
        .uid = TEST_VALID_ID,
        .label = "testLabel",
        .bundleName = "testBundleName",
        .userId = TEST_VALID_ID
    };
    std::vector<std::shared_ptr<NotificationRecord>> records;
    advancedNotificationService_->GetRecordFromTriggerNotificationList(parameter, records);
    EXPECT_EQ(records.size(), LIST_SIZE_ONE);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_006
 * @tc.name      : Remove all from trigger notification list.
 * @tc.desc      : Test RemoveAllFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_006, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->RemoveAllFromTriggerNotificationList(nullptr);

    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->bundleOption = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record2->bundleOption->SetBundleName("testBundleName");
    record2->bundleOption->SetUid(TEST_VALID_ID);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record3->bundleOption->SetBundleName("testBundleName");
    record3->bundleOption->SetUid(TEST_INVALID_ID);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);

    auto record4 = std::make_shared<NotificationRecord>();
    record4->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record4->bundleOption->SetBundleName("invalidBundleName");
    record4->bundleOption->SetUid(TEST_INVALID_ID);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record4);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FIVE);

    auto bundle = sptr<NotificationBundleOption>::MakeSptr();
    bundle->SetBundleName("testBundleName");
    bundle->SetUid(TEST_VALID_ID);
    advancedNotificationService_->RemoveAllFromTriggerNotificationList(bundle);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_THREE);
}

/**
 * @tc.number    : RemoveNotificationsFromTriggerNotificationList_007
 * @tc.name      : Remove Ntf by slot from trigger notification list.
 * @tc.desc      : Test RemoveNtfBySlotFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveNotificationsFromTriggerNotificationList_007, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    auto bundle = sptr<NotificationBundleOption>::MakeSptr();
    bundle->SetBundleName("testBundleName");
    bundle->SetUid(TEST_VALID_ID);
    auto slot = sptr<NotificationSlot>::MakeSptr();
    slot->SetType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    advancedNotificationService_->RemoveNtfBySlotFromTriggerNotificationList(nullptr, nullptr);
    advancedNotificationService_->RemoveNtfBySlotFromTriggerNotificationList(bundle, nullptr);
    advancedNotificationService_->RemoveNtfBySlotFromTriggerNotificationList(nullptr, slot);

    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.emplace_back(nullptr);

    auto record1 = std::make_shared<NotificationRecord>();
    record1->bundleOption = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record2->bundleOption->SetBundleName("testBundleName");
    record2->request = nullptr;
    advancedNotificationService_->triggerNotificationList_.emplace_back(record2);

    auto record3 = std::make_shared<NotificationRecord>();
    record3->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record3->bundleOption->SetBundleName("testBundleName");
    record3->request = sptr<NotificationRequest>::MakeSptr();
    record3->request->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record3);

    auto record4 = std::make_shared<NotificationRecord>();
    record4->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record4->bundleOption->SetBundleName("testBundleName");
    record4->bundleOption->SetUid(TEST_VALID_ID);
    record4->request = sptr<NotificationRequest>::MakeSptr();
    record4->request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record4);

    auto record5 = std::make_shared<NotificationRecord>();
    record5->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record5->bundleOption->SetBundleName("invalidBundleName");
    record5->bundleOption->SetUid(TEST_INVALID_ID);
    record5->request = sptr<NotificationRequest>::MakeSptr();
    record5->request->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    advancedNotificationService_->triggerNotificationList_.emplace_back(record5);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_SIX);
    advancedNotificationService_->RemoveNtfBySlotFromTriggerNotificationList(bundle, slot);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_FIVE);
}
}  // namespace Notification
}  // namespace OHOS
