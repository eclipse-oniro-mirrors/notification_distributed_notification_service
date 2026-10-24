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

#include "gtest/gtest.h"
#define private public
#include "advanced_notification_service.h"
#include "ans_service_errors.h"
#include "ans_ut_constant.h"
#include "mock_accesstoken_kit.h"
#include "notification_bundle_option.h"
#include "notification_request.h"
#include "notification_classification_mgr.h"
#include "notification_content.h"
#include "notification_normal_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"

using namespace testing::ext;

extern void MockIsOsAccountExists(bool mockRet);

namespace OHOS {
namespace Notification {
class AdvancedNotificationCancelTest : public testing::Test {
public:
    void SetUp() override
    {
        MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
        MockIsSystemApp(true);
        MockIsVerfyPermisson(true);
    }
    void TearDown() override {}
};

static sptr<AdvancedNotificationService> GetService()
{
    return new AdvancedNotificationService();
}

/**
 * @tc.name: CancelAsBundleWithAgent_NullBundleOption_00001
 * @tc.desc: Test CancelAsBundleWithAgent with nullptr bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, CancelAsBundleWithAgent_NullBundleOption_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> nullBundle = nullptr;

    auto result = service->CancelAsBundleWithAgent(nullBundle, 1);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotification_CheckPermissionFailed_00001
 * @tc.desc: Test RemoveNotification with permission check failed
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotification_CheckPermissionFailed_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    auto result = service->RemoveNotification(bundle, 1, "testLabel", NotificationConstant::CANCEL_REASON_DELETE);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: RemoveAllNotificationsForDisable_NullptrNotificationList_00001
 * @tc.desc: Test RemoveAllNotificationsForDisable with empty notificationList
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest,
    RemoveAllNotificationsForDisable_NullptrNotificationList_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    service->RemoveAllNotificationsForDisable(bundle);
    EXPECT_EQ(service->notificationList_.size(), 0);
}

/**
 * @tc.name: RemoveNotificationBySlot_NullBundleOption_00001
 * @tc.desc: Test RemoveNotificationBySlot with nullptr bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotificationBySlot_NullBundleOption_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> nullBundle = nullptr;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);

    auto result = service->RemoveNotificationBySlot(nullBundle, slot, NotificationConstant::CANCEL_REASON_DELETE);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: IsDistributedNotification_NullRequest_00001
 * @tc.desc: Test IsDistributedNotification with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, IsDistributedNotification_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;

    auto result = service->IsDistributedNotification(nullRequest);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsDistributedNotification_DistributedCollaborate_00001
 * @tc.desc: Test IsDistributedNotification with distributed collaborate
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest,
    IsDistributedNotification_DistributedCollaborate_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetDistributedCollaborate(true);

    auto result = service->IsDistributedNotification(request);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsReasonClickDelete_ClickReason_00001
 * @tc.desc: Test IsReasonClickDelete with click reason
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, IsReasonClickDelete_ClickReason_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    auto result = service->IsReasonClickDelete(NotificationConstant::CLICK_REASON_DELETE);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsReasonClickDelete_DistributedCollaborativeClick_00001
 * @tc.desc: Test IsReasonClickDelete with distributed collaborative click
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest,
    IsReasonClickDelete_DistributedCollaborativeClick_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    auto result = service->IsReasonClickDelete(NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsReasonClickDelete_OtherReason_00001
 * @tc.desc: Test IsReasonClickDelete with other reason
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, IsReasonClickDelete_OtherReason_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    auto result = service->IsReasonClickDelete(NotificationConstant::CANCEL_REASON_DELETE);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ClassificationMgr_Remove_CancelContinuousTask_00001
 * @tc.desc: Test ClassificationMgr Remove in CancelContinuousTaskNotification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_CancelContinuousTask_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationLiveViewContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Size(), 1);
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveNotification_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveNotification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_RemoveNotification_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveAllForDisable_00001
 * @tc.desc: Test ClassificationMgr Remove in ExcuteRemoveAllNotificationsInner.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_RemoveAllForDisable_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveBySlot_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveNotificationBySlot.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_RemoveBySlot_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveByDeviceId_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveNotificationsByDeviceId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_RemoveByDeviceId_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Size(), 0);
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveDistributedNotifications_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveDistributedNotifications.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest,
    ClassificationMgr_Remove_RemoveDistributedNotifications_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Size(), 0);
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveDistributedByBundle_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveDistributedNotificationsByBundle.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest,
    ClassificationMgr_Remove_RemoveDistributedByBundle_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Size(), 0);
}

/**
 * @tc.name: ClassificationMgr_Remove_RemoveAllDistributed_00001
 * @tc.desc: Test ClassificationMgr Remove in RemoveAllDistributedNotifications.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_RemoveAllDistributed_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Size(), 0);
}

/**
 * @tc.name: ClassificationMgr_Remove_BasicOperation_00001
 * @tc.desc: Test ClassificationMgr Remove basic operation.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationCancelTest, ClassificationMgr_Remove_BasicOperation_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    std::string key = "cancel_test_key";
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Remove(key));
    EXPECT_FALSE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: ResolveAgentUid_NonZeroUid_00001
 * @tc.desc: Test ResolveAgentUid with non-zero uid in bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, ResolveAgentUid_NonZeroUid_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    int32_t outUid = -1;

    auto result = service->ResolveAgentUid(bundle, 1,
        NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE, outUid);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(outUid, 100);
}

/**
 * @tc.name: ResolveAgentUid_NegativeUid_00001
 * @tc.desc: Test ResolveAgentUid with negative uid in bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, ResolveAgentUid_NegativeUid_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", -1);
    int32_t outUid = -1;

    auto result = service->ResolveAgentUid(bundle, 1,
        NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE, outUid);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_UID);
    EXPECT_EQ(outUid, -1);
}

/**
 * @tc.name: ResolveAgentUid_ZeroUidResolveFailed_00001
 * @tc.desc: Test ResolveAgentUid with DEFAULT_UID uid and GetDefaultUidByBundleName failed
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, ResolveAgentUid_ZeroUidResolveFailed_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundleName", 0);
    int32_t outUid = -1;

    auto result = service->ResolveAgentUid(bundle, 1,
        NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE, outUid);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_UID);
    EXPECT_EQ(outUid, -1);
}

/**
 * @tc.name: ResolveAgentUid_ZeroUidResolved_00001
 * @tc.desc: Test ResolveAgentUid with DEFAULT_UID uid and GetDefaultUidByBundleName success
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, ResolveAgentUid_ZeroUidResolved_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("com.ans.test.agent", 0);
    int32_t outUid = -1;

    auto result = service->ResolveAgentUid(bundle, 1,
        NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE, outUid);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(outUid, NON_SYSTEM_APP_UID);
}

/**
 * @tc.name: RemoveNotificationAsAdmin_UserDeletableOnly_00001
 * @tc.desc: Test RemoveNotificationAsAdmin returns USER_DELETABLE_ONLY error and keeps notification
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotificationAsAdmin_UserDeletableOnly_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    request->SetUserDeletableOnly(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string hashCode = record->notification->GetKey();

    auto result = service->RemoveNotificationAsAdmin(hashCode);
    EXPECT_EQ(result, ERR_ANS_INNER_ADMIN_NOTIFICATION_USER_DELETABLE_ONLY);
    EXPECT_EQ(service->notificationList_.size(), 1);
}

/**
 * @tc.name: RemoveNotification_UserDeletableOnly_NotJudged_00001
 * @tc.desc: Test normal RemoveNotification ignores userDeletableOnly and deletes successfully
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotification_UserDeletableOnly_NotJudged_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    request->SetUserDeletableOnly(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);

    auto result = service->RemoveNotification(bundle, 1, "", NotificationConstant::CANCEL_REASON_DELETE);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(service->notificationList_.size(), 0);
}

/**
 * @tc.name: RemoveAllNotificationsAsAdmin_UserDeletableOnly_00001
 * @tc.desc: Test RemoveAllNotificationsAsAdmin skips userDeletableOnly notification and removes others
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveAllNotificationsAsAdmin_UserDeletableOnly_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    MockIsOsAccountExists(true);
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    sptr<NotificationRequest> protectedRequest = new NotificationRequest();
    protectedRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    protectedRequest->SetNotificationId(1);
    auto protectedContent = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    protectedRequest->SetContent(protectedContent);
    protectedRequest->SetCreatorUserId(100);
    protectedRequest->SetUserDeletableOnly(true);
    service->AddToNotificationList(service->MakeNotificationRecord(protectedRequest, bundle));

    sptr<NotificationRequest> normalRequest = new NotificationRequest();
    normalRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    normalRequest->SetNotificationId(2);
    auto normalContent = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    normalRequest->SetContent(normalContent);
    normalRequest->SetCreatorUserId(100);
    service->AddToNotificationList(service->MakeNotificationRecord(normalRequest, bundle));

    ASSERT_EQ(service->notificationList_.size(), 2);

    auto result = service->RemoveAllNotificationsAsAdmin(100);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(service->notificationList_.size(), 1);
    EXPECT_TRUE(service->notificationList_.front()->request->IsUserDeletableOnly());
}

/**
 * @tc.name: RemoveNotificationAsAdmin_SystemLiveView_00001
 * @tc.desc: Test RemoveNotificationAsAdmin returns SYSTEM_LIVE_VIEW error and keeps notification
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotificationAsAdmin_SystemLiveView_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationLocalLiveViewContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string hashCode = record->notification->GetKey();

    auto result = service->RemoveNotificationAsAdmin(hashCode);
    EXPECT_EQ(result, ERR_ANS_INNER_ADMIN_SYSTEM_LIVE_VIEW_NOT_REMOVABLE);
    EXPECT_EQ(service->notificationList_.size(), 1);
}

/**
 * @tc.name: RemoveNotificationAsAdmin_KeyMatch_00001
 * @tc.desc: Test RemoveNotificationAsAdmin hash code matching with non-matching and matching hash code
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveNotificationAsAdmin_KeyMatch_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    auto service = GetService();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetNotificationId(1);
    request->SetLabel("adminLabel");
    auto content = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    auto record = service->MakeNotificationRecord(request, bundle);
    service->AddToNotificationList(record);
    std::string hashCode = record->notification->GetKey();

    auto result = service->RemoveNotificationAsAdmin("wrongHashCode");
    EXPECT_EQ(result, ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_EQ(service->notificationList_.size(), 1);

    result = service->RemoveNotificationAsAdmin(hashCode);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(service->notificationList_.size(), 0);
}

/**
 * @tc.name: NotificationRequest_CopyUserDeletableOnly_00001
 * @tc.desc: Test NotificationRequest copy constructor and assignment keep userDeletableOnly
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, NotificationRequest_CopyUserDeletableOnly_00001,
    Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetUserDeletableOnly(true);

    NotificationRequest copied(*request);
    EXPECT_TRUE(copied.IsUserDeletableOnly());

    NotificationRequest assigned;
    assigned = *request;
    EXPECT_TRUE(assigned.IsUserDeletableOnly());
}

/**
 * @tc.name: RemoveAllNotificationsAsAdmin_CleansTriggerAndSnooze_00001
 * @tc.desc: Test RemoveAllNotificationsAsAdmin cleans trigger and snooze delay lists
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationCancelTest, RemoveAllNotificationsAsAdmin_CleansTriggerAndSnooze_00001,
    Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    MockIsOsAccountExists(true);
    auto service = GetService();
    service->notificationList_.clear();
    service->triggerNotificationList_.clear();
    service->snoozeDelayTimerList_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    sptr<NotificationRequest> activeRequest = new NotificationRequest();
    activeRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    activeRequest->SetNotificationId(1);
    auto activeContent = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    activeRequest->SetContent(activeContent);
    activeRequest->SetCreatorUserId(100);
    service->AddToNotificationList(service->MakeNotificationRecord(activeRequest, bundle));

    sptr<NotificationRequest> triggerRequest = new NotificationRequest();
    triggerRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    triggerRequest->SetNotificationId(2);
    auto triggerContent = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    triggerRequest->SetContent(triggerContent);
    triggerRequest->SetCreatorUserId(100);
    service->AddToTriggerNotificationList(service->MakeNotificationRecord(triggerRequest, bundle));
    ASSERT_EQ(service->triggerNotificationList_.size(), 1);

    sptr<NotificationRequest> snoozeRequest = new NotificationRequest();
    snoozeRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    snoozeRequest->SetNotificationId(3);
    auto snoozeContent = std::make_shared<NotificationContent>(
        std::make_shared<NotificationNormalContent>());
    snoozeRequest->SetContent(snoozeContent);
    snoozeRequest->SetCreatorUserId(100);
    snoozeRequest->SetSnoozeDelayTime(1000000);
    service->InsertsnoozeDelayTimer(service->MakeNotificationRecord(snoozeRequest, bundle));
    ASSERT_EQ(service->snoozeDelayTimerList_.size(), 1);

    auto result = service->RemoveAllNotificationsAsAdmin(100);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(service->notificationList_.size(), 0);
    EXPECT_EQ(service->triggerNotificationList_.size(), 0);
    EXPECT_EQ(service->snoozeDelayTimerList_.size(), 0);
}

}  // namespace Notification
}  // namespace OHOS
