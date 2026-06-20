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
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemAppByFullTokenID(bool isSystemApp);

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
    MockIsVerfyPermisson(true);
    MockIsSystemAppByFullTokenID(true);
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

    auto record = advancedNotificationService_->GetRecordFromTriggerNotificationList(parameter);
    EXPECT_NE(record, nullptr);
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

/**
 * @tc.number    : GetRecordFromTriggerNotificationList_001
 * @tc.name      : Get record from trigger notificationList.
 * @tc.desc      : Test GetRecordFromTriggerNotificationList.
 */
HWTEST_F(AnsGeofenceServiceTest, GetRecordFromTriggerNotificationList_001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    AdvancedNotificationService::GetRecordParameter parameter{
        .notificationId = TEST_VALID_ID,
        .uid = TEST_VALID_ID,
        .label = "testLabel",
        .bundleName = "testBundleName",
        .userId = TEST_VALID_ID
    };

    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.push_back(nullptr);
    auto result = advancedNotificationService_->GetRecordFromTriggerNotificationList(parameter);
    EXPECT_EQ(result, nullptr);

    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
    record->bundleOption->SetBundleName("");
    record->bundleOption->SetUid(TEST_VALID_ID);
    record->request = sptr<NotificationRequest>::MakeSptr();
    record->request->SetNotificationId(TEST_VALID_ID);
    record->request->SetLabel("testLabel");
    record->request->SetReceiverUserId(TEST_VALID_ID);
    record->request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    record->request->SetContent(content);
    record->notification = sptr<Notification>::MakeSptr(record->request);
    record->bundleOption->SetUid(TEST_VALID_ID);
    record->bundleOption->SetBundleName("testBundleName");
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    result = advancedNotificationService_->GetRecordFromTriggerNotificationList(parameter);
    EXPECT_NE(result, nullptr);

    advancedNotificationService_->triggerNotificationList_.push_back(record);
    result = advancedNotificationService_->GetRecordFromTriggerNotificationList(parameter);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.number    : SetGeofenceEnabled_00001
 * @tc.name      : SetGeofenceEnabled with permission denied
 * @tc.desc      : Test SetGeofenceEnabled when permission check fails.
 */
HWTEST_F(AnsGeofenceServiceTest, SetGeofenceEnabled_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);
    MockIsSystemAppByFullTokenID(false);

    auto result = advancedNotificationService_->SetGeofenceEnabled(true);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number    : IsGeofenceEnabled_00001
 * @tc.name      : IsGeofenceEnabled successfully
 * @tc.desc      : Test IsGeofenceEnabled returns enabled status correctly.
 */
HWTEST_F(AnsGeofenceServiceTest, IsGeofenceEnabled_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    bool enabled = false;

    auto result = advancedNotificationService_->IsGeofenceEnabled(enabled);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : OnNotifyDelayedNotification_00001
 * @tc.name      : OnNotifyDelayedNotification with null request
 * @tc.desc      : Test OnNotifyDelayedNotification when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, OnNotifyDelayedNotification_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = nullptr;

    auto result = advancedNotificationService_->OnNotifyDelayedNotification(parameter);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : OnNotifyDelayedNotification_00002
 * @tc.name      : OnNotifyDelayedNotification with null trigger
 * @tc.desc      : Test OnNotifyDelayedNotification when trigger is null.
 */
HWTEST_F(AnsGeofenceServiceTest, OnNotifyDelayedNotification_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = new NotificationRequest();

    auto result = advancedNotificationService_->OnNotifyDelayedNotification(parameter);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : ClearDelayNotification_00001
 * @tc.name      : ClearDelayNotification with empty triggerKeys
 * @tc.desc      : Test ClearDelayNotification with empty triggerKeys vector.
 */
HWTEST_F(AnsGeofenceServiceTest, ClearDelayNotification_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    std::vector<std::string> triggerKeys;
    std::vector<int32_t> userIds;

    auto result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : PublishDelayedNotification_00001
 * @tc.name      : PublishDelayedNotification permission denied
 * @tc.desc      : Test PublishDelayedNotification when permission check fails.
 */
HWTEST_F(AnsGeofenceServiceTest, PublishDelayedNotification_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    auto result = advancedNotificationService_->PublishDelayedNotification("testTriggerKey", TEST_VALID_ID);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetDelayedNotificationParameterByTriggerKey_00001
 * @tc.name      : GetDelayedNotificationParameterByTriggerKey not found
 * @tc.desc      : Test GetDelayedNotificationParameterByTriggerKey when record not found.
 */
HWTEST_F(AnsGeofenceServiceTest, GetDelayedNotificationParameterByTriggerKey_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::shared_ptr<NotificationRecord> record = nullptr;

    auto result = advancedNotificationService_->GetDelayedNotificationParameterByTriggerKey(
        "testTriggerKey", parameter, record);
    EXPECT_EQ(result, ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : UpdateTriggerRequest_00001
 * @tc.name      : UpdateTriggerRequest with null request
 * @tc.desc      : Test UpdateTriggerRequest when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, UpdateTriggerRequest_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = nullptr;

    advancedNotificationService_->UpdateTriggerRequest(request);
    EXPECT_EQ(request, nullptr);
}

/**
 * @tc.number    : AddToTriggerNotificationList_00001
 * @tc.name      : AddToTriggerNotificationList successfully
 * @tc.desc      : Test AddToTriggerNotificationList adds record to list.
 */
HWTEST_F(AnsGeofenceServiceTest, AddToTriggerNotificationList_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);

    advancedNotificationService_->AddToTriggerNotificationList(record);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), LIST_SIZE_ONE);
}

/**
 * @tc.number    : FindGeofenceNotificationRecordByTriggerKey_00001
 * @tc.name      : FindGeofenceNotificationRecordByTriggerKey not found
 * @tc.desc      : Test FindGeofenceNotificationRecordByTriggerKey when record not found.
 */
HWTEST_F(AnsGeofenceServiceTest, FindGeofenceNotificationRecordByTriggerKey_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    std::shared_ptr<NotificationRecord> record = nullptr;

    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey("testTriggerKey", record);
    EXPECT_EQ(record, nullptr);
}

/**
 * @tc.number    : FindGeofenceNotificationRecordByKey_00001
 * @tc.name      : FindGeofenceNotificationRecordByKey not found
 * @tc.desc      : Test FindGeofenceNotificationRecordByKey when record not found.
 */
HWTEST_F(AnsGeofenceServiceTest, FindGeofenceNotificationRecordByKey_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    std::vector<std::shared_ptr<NotificationRecord>> records;

    advancedNotificationService_->FindGeofenceNotificationRecordByKey("testKey", records);
    EXPECT_EQ(records.size(), 0);
}

/**
 * @tc.number    : FindNotificationRecordByKey_00001
 * @tc.name      : FindNotificationRecordByKey not found
 * @tc.desc      : Test FindNotificationRecordByKey when record not found.
 */
HWTEST_F(AnsGeofenceServiceTest, FindNotificationRecordByKey_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->notificationList_.clear();
    std::shared_ptr<NotificationRecord> record = nullptr;

    advancedNotificationService_->FindNotificationRecordByKey("testKey", record);
    EXPECT_EQ(record, nullptr);
}

/**
 * @tc.number    : SetGeofenceTriggerTimer_00001
 * @tc.name      : SetGeofenceTriggerTimer with null trigger
 * @tc.desc      : Test SetGeofenceTriggerTimer when trigger is null.
 */
HWTEST_F(AnsGeofenceServiceTest, SetGeofenceTriggerTimer_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);

    auto result = advancedNotificationService_->SetGeofenceTriggerTimer(record);
    EXPECT_EQ(result, ERR_ANS_INNER_TASK_ERR);
}

/**
 * @tc.number    : CancelGeofenceTriggerTimer_00001
 * @tc.name      : CancelGeofenceTriggerTimer successfully
 * @tc.desc      : Test CancelGeofenceTriggerTimer cancels timer correctly.
 */
HWTEST_F(AnsGeofenceServiceTest, CancelGeofenceTriggerTimer_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->request->SetGeofenceTriggerDeadLine(TEST_VALID_ID);
    record->notification = new Notification(record->request);
    record->notification->SetGeofenceTriggerTimer(TEST_VALID_ID);

    advancedNotificationService_->CancelGeofenceTriggerTimer(record);
    EXPECT_EQ(record->request->GetGeofenceTriggerDeadLine(), 0);
}

/**
 * @tc.number    : CheckGeofenceNotificationRequest_00001
 * @tc.name      : CheckGeofenceNotificationRequest with null request
 * @tc.desc      : Test CheckGeofenceNotificationRequest when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, CheckGeofenceNotificationRequest_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = nullptr;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", TEST_VALID_ID);

    auto result = advancedNotificationService_->CheckGeofenceNotificationRequest(request, bundleOption);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveTriggerNotificationListByTriggerKey_00001
 * @tc.name      : RemoveTriggerNotificationListByTriggerKey successfully
 * @tc.desc      : Test RemoveTriggerNotificationListByTriggerKey removes record correctly.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveTriggerNotificationListByTriggerKey_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    advancedNotificationService_->RemoveTriggerNotificationListByTriggerKey("secure_trigger_live_view___-1_0___0_");
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : TriggerNotificationRecordFilter_00001
 * @tc.name      : TriggerNotificationRecordFilter with null record
 * @tc.desc      : Test TriggerNotificationRecordFilter when record is null.
 */
HWTEST_F(AnsGeofenceServiceTest, TriggerNotificationRecordFilter_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    std::shared_ptr<NotificationRecord> record = nullptr;

    auto result = advancedNotificationService_->TriggerNotificationRecordFilter(record);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSwitchStatus_00001
 * @tc.name      : CheckSwitchStatus with null request
 * @tc.desc      : Test CheckSwitchStatus when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, CheckSwitchStatus_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = nullptr;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", TEST_VALID_ID);

    auto result = advancedNotificationService_->CheckSwitchStatus(request, bundleOption);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : IsGeofenceNotificationRequest_00001
 * @tc.name      : IsGeofenceNotificationRequest with null request
 * @tc.desc      : Test IsGeofenceNotificationRequest when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, IsGeofenceNotificationRequest_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = nullptr;

    auto result = advancedNotificationService_->IsGeofenceNotificationRequest(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsGeofenceNotificationRequest_00002
 * @tc.name      : IsGeofenceNotificationRequest with trigger live view
 * @tc.desc      : Test IsGeofenceNotificationRequest when request is trigger live view.
 */
HWTEST_F(AnsGeofenceServiceTest, IsGeofenceNotificationRequest_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    auto result = advancedNotificationService_->IsGeofenceNotificationRequest(request);
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : IsExistsGeofence_00001
 * @tc.name      : IsExistsGeofence with null request
 * @tc.desc      : Test IsExistsGeofence when request is null.
 */
HWTEST_F(AnsGeofenceServiceTest, IsExistsGeofence_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = nullptr;

    auto result = advancedNotificationService_->IsExistsGeofence(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsExistsGeofence_00002
 * @tc.name      : IsExistsGeofence not found
 * @tc.desc      : Test IsExistsGeofence when geofence does not exist.
 */
HWTEST_F(AnsGeofenceServiceTest, IsExistsGeofence_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest();

    auto result = advancedNotificationService_->IsExistsGeofence(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsExistsGeofence_00003
 * @tc.name      : IsExistsGeofence found
 * @tc.desc      : Test IsExistsGeofence when geofence exists.
 */
HWTEST_F(AnsGeofenceServiceTest, IsExistsGeofence_00003, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    sptr<NotificationRequest> request = new NotificationRequest();

    auto result = advancedNotificationService_->IsExistsGeofence(request);
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : ExecuteCancelGroupCancelFromTriggerNotificationList_00001
 * @tc.name      : ExecuteCancelGroupCancelFromTriggerNotificationList successfully
 * @tc.desc      : Test ExecuteCancelGroupCancelFromTriggerNotificationList removes group notifications.
 */
HWTEST_F(AnsGeofenceServiceTest, ExecuteCancelGroupCancelFromTriggerNotificationList_00001,
    Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", TEST_VALID_ID);

    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = bundleOption;
    record->request = new NotificationRequest();
    record->request->SetGroupName("testGroup");
    record->notification = new Notification(record->request);
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    advancedNotificationService_->ExecuteCancelGroupCancelFromTriggerNotificationList(bundleOption, "testGroup");
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : RemoveFromTriggerNotificationList_00001
 * @tc.name      : RemoveFromTriggerNotificationList by key
 * @tc.desc      : Test RemoveFromTriggerNotificationList removes record by key.
 */
HWTEST_F(AnsGeofenceServiceTest, RemoveFromTriggerNotificationList_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();
    auto record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);
    record->notification->SetKey("testKey");
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    advancedNotificationService_->RemoveFromTriggerNotificationList("testKey");
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : GeneratePublishNotificationParameter_00001
 * @tc.name      : GeneratePublishNotificationParameter successfully
 * @tc.desc      : Test GeneratePublishNotificationParameter generates parameter correctly.
 */
HWTEST_F(AnsGeofenceServiceTest, GeneratePublishNotificationParameter_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", TEST_VALID_ID);
    AdvancedNotificationService::PublishNotificationParameter parameter;

    advancedNotificationService_->GeneratePublishNotificationParameter(request, bundleOption, false, parameter);
    EXPECT_EQ(parameter.request, request);
    EXPECT_EQ(parameter.bundleOption, bundleOption);
}
}  // namespace Notification
}  // namespace OHOS
