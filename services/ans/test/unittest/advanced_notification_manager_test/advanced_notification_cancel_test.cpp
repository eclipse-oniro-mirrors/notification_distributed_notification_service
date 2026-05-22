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
#include "notification_bundle_option.h"
#include "notification_request.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationCancelTest : public testing::Test {
public:
    void SetUp() override
    {
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
 * @tc.name: CancelAll_SynchronizerNullptr_00001
 * @tc.desc: Test CancelAll with nullptr synchronizer
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationCancelTest, CancelAll_SynchronizerNullptr_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->CancelAll("", nullptr);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    
    auto result = service->CancelAsBundleWithAgent(nullBundle, 1, nullptr);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    EXPECT_EQ(result, ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(result, ERR_ANS_INVALID_BUNDLE);
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

}  // namespace Notification
}  // namespace OHOS