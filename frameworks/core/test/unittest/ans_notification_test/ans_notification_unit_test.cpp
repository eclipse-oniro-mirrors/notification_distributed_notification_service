/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "ans_notification.h"
#include "ans_subscriber_proxy.h"
#include "ans_manager_proxy.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "mock_i_remote_object.h"
#include "notification.h"
#include "singleton.h"
#include "notification_subscriber.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

extern void MockWriteInterfaceToken(bool mockRet);

class AnsNotificationUnitTest : public testing::Test {
public:
    AnsNotificationUnitTest() {}

    virtual ~AnsNotificationUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<AnsNotification> ans_;
    sptr<AnsManagerInterface> ansManagerProxy_{nullptr};
};

void AnsNotificationUnitTest::SetUpTestCase()
{
    MockWriteInterfaceToken(true);
}

void AnsNotificationUnitTest::TearDownTestCase() {}

void AnsNotificationUnitTest::SetUp()
{
    if (!ans_) {
        ans_ = DelayedSingleton<AnsNotification>::GetInstance();
    }
}

void AnsNotificationUnitTest::TearDown() {}

/*
 * @tc.name: GetAnsManagerProxy_0100
 * @tc.desc: test GetAnsManagerProxy return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetAnsManagerProxy_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: AddSlotByType_0100
 * @tc.desc: test AddSlotByType ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, AddSlotByType_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    ErrCode ret1 = ans_->AddSlotByType(slotType);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->RemoveNotificationSlot(slotType);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveAllSlots_0100
 * @tc.desc: test RemoveAllSlots ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RemoveAllSlots_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    ErrCode ret1 = ans_->RemoveAllSlots();
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlot_0100
 * @tc.desc: test GetNotificationSlot ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlot_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    sptr<NotificationSlot> slot = new NotificationSlot();
    ErrCode ret1 = ans_->GetNotificationSlot(slotType, slot);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<sptr<NotificationSlot>> slots;
    slots.emplace_back(slot);
    ErrCode ret2 = ans_->GetNotificationSlots(slots);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<NotificationSlot> nslots;
    NotificationSlot notificationSlot;
    nslots.emplace_back(notificationSlot);
    ErrCode ret3 = ans_->AddNotificationSlots(nslots);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotNumAsBundle_0100
 * @tc.desc: test GetNotificationSlotNumAsBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotNumAsBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    uint64_t num = 10;
    ErrCode ret1 = ans_->GetNotificationSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: PublishNotification_0100
 * @tc.desc: test PublishNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, PublishNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string label = "this is label";
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret1 = ans_->PublishNotification(label, request);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string deviceId = "this is deviceId";
    ErrCode ret2 = ans_->PublishNotification(request, deviceId);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t notificationId = 10;
    ErrCode ret3 = ans_->CancelNotification(label, notificationId);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->CancelAllNotifications();
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string representativeBundle = "this is representativeBundle";
    int32_t userId = 5;
    ErrCode ret5 = ans_->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetActiveNotificationNums_0100
 * @tc.desc: test GetActiveNotificationNums ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetActiveNotificationNums_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    uint64_t num = 4;
    ErrCode ret1 = ans_->GetActiveNotificationNums(num);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<sptr<NotificationRequest>> request;
    ErrCode ret2 = ans_->GetActiveNotifications(request);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    sptr<NotificationSortingMap> sortingMap = new NotificationSortingMap();
    ErrCode ret3 = ans_->GetCurrentAppSorting(sortingMap);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string agent = "this is agent";
    ErrCode ret4 = ans_->SetNotificationAgent(agent);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->GetNotificationAgent(agent);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: CanPublishNotificationAsBundle_0100
 * @tc.desc: test CanPublishNotificationAsBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CanPublishNotificationAsBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string representativeBundle = "this is representativeBundle";
    bool canPublish = true;
    ErrCode ret1 = ans_->CanPublishNotificationAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string representativeBundle0 = "";
    ErrCode ret2 = ans_->CanPublishNotificationAsBundle(representativeBundle0, canPublish);
    EXPECT_EQ(ret2, ERR_ANS_INVALID_PARAM);
    NotificationRequest request;
    ErrCode ret3 = ans_->PublishNotificationAsBundle(representativeBundle0, request);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret5 = ans_->PublishNotificationAsBundle(representativeBundle, request);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetNotificationBadgeNum_0100
 * @tc.desc: test SetNotificationBadgeNum ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationBadgeNum_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    ErrCode ret1 = ans_->SetNotificationBadgeNum();
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t num = 3;
    ErrCode ret2 = ans_->SetNotificationBadgeNum(num);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsAllowedNotify_0100
 * @tc.desc: test IsAllowedNotify ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsAllowedNotify_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    bool allowed = true;
    ErrCode ret1 = ans_->IsAllowedNotify(allowed);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->IsAllowedNotify(bundleOption, allowed);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RequestEnableNotification_0100
 * @tc.desc: test RequestEnableNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RequestEnableNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string deviceId = "this is deviceId";
    ErrCode ret1 = ans_->RequestEnableNotification(deviceId);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool suspended = true;
    ErrCode ret2 = ans_->AreNotificationsSuspended(suspended);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool hasPermission = true;
    ErrCode ret3 = ans_->HasNotificationPolicyAccessPermission(hasPermission);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetBundleImportance_0100
 * @tc.desc: test GetBundleImportance ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetBundleImportance_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationSlot::NotificationLevel importance = NotificationSlot::NotificationLevel::LEVEL_NONE;
    ErrCode ret1 = ans_->GetBundleImportance(importance);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveNotification_0100
 * @tc.desc: test RemoveNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RemoveNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string key = "";
    int32_t removeReason = 10;
    ErrCode ret1 = ans_->RemoveNotification(key, removeReason);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    std::string key1 = "this is key1";
    ErrCode ret2 = ans_->RemoveNotification(key1, removeReason);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    int32_t notificationId = 2;
    std::string label = "this is label";
    ErrCode ret3 = ans_->RemoveNotification(bundleOption, notificationId, label, removeReason);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->RemoveNotificationsByBundle(bundleOption);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->RemoveNotifications();
    EXPECT_EQ(ret6, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotsForBundle_0100
 * @tc.desc: test GetNotificationSlotsForBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotsForBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    sptr<NotificationSlot> slot = new NotificationSlot();
    std::vector<sptr<NotificationSlot>> slots;
    slots.emplace_back(slot);
    ErrCode ret1 = ans_->GetNotificationSlotsForBundle(bundleOption, slots);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->UpdateNotificationSlots(bundleOption, slots);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetNotificationsEnabledForAllBundles_0100
 * @tc.desc: test SetNotificationsEnabledForAllBundles ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationsEnabledForAllBundles_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string deviceId = "this is deviceId";
    bool enabled = true;
    ErrCode ret1 = ans_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->SetNotificationsEnabledForDefaultBundle(deviceId, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, enabled);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->SetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ret6, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: CancelGroup_0100
 * @tc.desc: test CancelGroup ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CancelGroup_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string groupName = "this is groupName";
    ErrCode ret1 = ans_->CancelGroup(groupName);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret2 = ans_->RemoveGroupByBundle(bundleOption, groupName);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetDoNotDisturbDate_0100
 * @tc.desc: test SetDoNotDisturbDate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetDoNotDisturbDate_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationDoNotDisturbDate doNotDisturbDate;
    ErrCode ret1 = ans_->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool doesSupport = true;
    ErrCode ret3 = ans_->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: PublishContinuousTaskNotification_0100
 * @tc.desc: test PublishContinuousTaskNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, PublishContinuousTaskNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret1 = ans_->PublishContinuousTaskNotification(request);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string label = "this is label";
    int32_t notificationId = 3;
    ErrCode ret2 = ans_->CancelContinuousTaskNotification(label, notificationId);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsDistributedEnabled_0100
 * @tc.desc: test IsDistributedEnabled ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsDistributedEnabled_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    bool enabled = true;
    ErrCode ret1 = ans_->IsDistributedEnabled(enabled);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->EnableDistributed(enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    ErrCode ret3 = ans_->EnableDistributedByBundle(bundleOption, enabled);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->EnableDistributedSelf(enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetDeviceRemindType_0100
 * @tc.desc: test GetDeviceRemindType ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetDeviceRemindType_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::NONE;
    ErrCode ret1 = ans_->GetDeviceRemindType(remindType);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ReminderRequest reminder;
    ErrCode ret2 = ans_->PublishReminder(reminder);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t reminderId = 1;
    ErrCode ret3 = ans_->CancelReminder(reminderId);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->CancelAllReminders();
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<sptr<ReminderRequest>> validReminders;
    ErrCode ret5 = ans_->GetValidReminders(validReminders);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsSupportTemplate_0100
 * @tc.desc: test IsSupportTemplate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsSupportTemplate_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string templateName = "this is templateName";
    bool support = true;
    ErrCode ret1 = ans_->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t userId = -1;
    bool allowed = true;
    ErrCode ret2 = ans_->IsAllowedNotify(userId, allowed);
    EXPECT_EQ(ret2, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret3 = ans_->IsAllowedNotify(userId1, allowed);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool enabled = true;
    ErrCode ret4 = ans_->SetNotificationsEnabledForAllBundles(userId, enabled);
    EXPECT_EQ(ret4, ERR_ANS_INVALID_PARAM);
    ErrCode ret5 = ans_->SetNotificationsEnabledForAllBundles(userId1, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->RemoveNotifications(userId);
    EXPECT_EQ(ret6, ERR_ANS_INVALID_PARAM);
    ErrCode ret7 = ans_->RemoveNotifications(userId1);
    EXPECT_EQ(ret7, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetDoNotDisturbDate_0200
 * @tc.desc: test SetDoNotDisturbDate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetDoNotDisturbDate_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    int32_t userId = -1;
    NotificationDoNotDisturbDate doNotDisturbDate;
    ErrCode ret1 = ans_->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret2 = ans_->SetDoNotDisturbDate(userId1, doNotDisturbDate);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    ErrCode ret4 = ans_->GetDoNotDisturbDate(userId1, doNotDisturbDate);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetEnabledForBundleSlot_0100
 * @tc.desc: test SetEnabledForBundleSlot ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetEnabledForBundleSlot_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    bool enabled = true;
    ErrCode ret1 = ans_->SetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: ShellDump_0100
 * @tc.desc: test ShellDump ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, ShellDump_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string cmd = "this is cmd";
    std::string bundle = "this is bundle";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    ErrCode ret1 = ans_->ShellDump(cmd, bundle, userId, dumpInfo);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetSyncNotificationEnabledWithoutApp_0100
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetSyncNotificationEnabledWithoutApp_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    int32_t userId = -1;
    bool enabled = true;
    ErrCode ret1 = ans_->SetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret2 = ans_->SetSyncNotificationEnabledWithoutApp(userId1, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->GetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    ErrCode ret4 = ans_->GetSyncNotificationEnabledWithoutApp(userId1, enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
}