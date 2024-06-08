/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "ans_ut_constant.h"
#include "ans_dialog_host_client.h"
#include "mock_push_callback_stub.h"

extern void MockIsOsAccountExists(bool exists);

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

class AnsPublishServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddNotification(int notificationId, const sptr<NotificationBundleOption> &bundle);
    void RegisterPushCheck();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsPublishServiceTest::advancedNotificationService_ = nullptr;

void AnsPublishServiceTest::SetUpTestCase() {}

void AnsPublishServiceTest::TearDownTestCase() {}

void AnsPublishServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance().ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->CancelAll();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsPublishServiceTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

void AnsPublishServiceTest::TestAddNotification(int notificationId, const sptr<NotificationBundleOption> &bundle)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(1);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
}

void AnsPublishServiceTest::RegisterPushCheck()
{
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    checkRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    EXPECT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), ERR_OK);
}
/**
 * @tc.name: Publish_00001
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto localLiveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveContent);
    request->SetContent(content);
    request->SetCreatorUid(1);
    request->SetOwnerUid(1);
    MockIsOsAccountExists(true);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: Publish_00002
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    request->SetRemoveAllowed(false);
    request->SetInProgress(true);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERR_OK);
}


/**
 * @tc.name: Publish_00003
 * @tc.desc: Publish live_view notification once
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    RegisterPushCheck();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERR_OK);

    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    ret = advancedNotificationService_->GetSlotByType(slotType, slot);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(1, slot->GetAuthorizedStatus());
    EXPECT_EQ(1, slot->GetAuthHintCnt());
}

/**
 * @tc.name: Publish_00004
 * @tc.desc: Publish live_view notification twice
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    RegisterPushCheck();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERR_OK);

    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetNotificationId(2);
    request2->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request2->SetContent(content);
    ret = advancedNotificationService_->Publish(label, request2);
    ASSERT_EQ(ret, (int)ERR_OK);

    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    ret = advancedNotificationService_->GetSlotByType(slotType, slot);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(0, slot->GetAuthorizedStatus());
    EXPECT_EQ(2, slot->GetAuthHintCnt());
}

/**
 * @tc.name: Publish_00005
 * @tc.desc: Publish test receiver user and checkUserExists is true
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00005, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    request->SetReceiverUserId(101);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    MockIsOsAccountExists(true);
    RegisterPushCheck();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: Publish_00006
 * @tc.desc: Publish test receiver user and checkUserExists is false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00006, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(1);
    request->SetReceiverUserId(101);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    MockIsOsAccountExists(false);

    auto ret = advancedNotificationService_->Publish(label, request);
    EXPECT_EQ(ret, (int)ERROR_USER_NOT_EXIST);
}

/**
 * @tc.name: DeleteByBundle_00001
 * @tc.desc: Test DeleteByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteByBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    auto ret = advancedNotificationService_->DeleteByBundle(bundleOption);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: DeleteByBundle_00002
 * @tc.desc: Test DeleteByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteByBundle_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->DeleteByBundle(bundle);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DeleteByBundle_00003
 * @tc.desc: Test DeleteByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteByBundle_00003, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    TestAddNotification(1, bundle);
    auto ret = advancedNotificationService_->DeleteByBundle(bundle);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.name: DeleteAll_00001
 * @tc.desc: Test DeleteAll
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteAll_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->DeleteAll();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetShowBadgeEnabledForBundle_00001
 * @tc.desc: Test SetShowBadgeEnabledForBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetShowBadgeEnabledForBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);

    bool enabled = false;
    ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetShowBadgeEnabledForBundle_00002
 * @tc.desc: Test SetShowBadgeEnabledForBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetShowBadgeEnabledForBundle_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundle, true);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enabled = false;
    ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetShowBadgeEnabled_00001
 * @tc.desc: Test GetShowBadgeEnabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, GetShowBadgeEnabled_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    bool enabled = false;
    auto ret = advancedNotificationService_->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetShowBadgeEnabled_00002
 * @tc.desc: Test GetShowBadgeEnabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, GetShowBadgeEnabled_00002, Function | SmallTest | Level1)
{
    bool enabled = true;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    auto ret = advancedNotificationService_->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(enabled, false);
}

/**
 * @tc.name: RequestEnableNotification_00001
 * @tc.desc: Test RequestEnableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RequestEnableNotification_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "deviceId";
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    sptr<IRemoteObject> callerToken = nullptr;

    auto ret = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), false);
    EXPECT_EQ(ret, (int)ERR_OK);

    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ret, (int)ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: RequestEnableNotification_00002
 * @tc.desc: Test RequestEnableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RequestEnableNotification_00002, Function | SmallTest | Level1)
{
    std::string deviceId = "deviceId";
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    sptr<IRemoteObject> callerToken = nullptr;

    auto ret = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true);
    EXPECT_EQ(ret, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: RequestEnableNotification_00003
 * @tc.desc: Test RequestEnableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RequestEnableNotification_00003, Function | SmallTest | Level1)
{
    std::string deviceId = "deviceId";
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    sptr<IRemoteObject> callerToken = nullptr;

    auto ret = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), false);
    EXPECT_EQ(ret, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);

    auto bundle = advancedNotificationService_->GenerateBundleOption();
    NotificationPreferences::GetInstance().SetHasPoppedDialog(bundle, true);

    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);

    NotificationPreferences::GetInstance().SetHasPoppedDialog(bundle, false);
    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles_00001
 * @tc.desc: Test SetNotificationsEnabledForAllBundles
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetNotificationsEnabledForAllBundles_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    bool enabled = false;
    auto ret = advancedNotificationService_->SetNotificationsEnabledForAllBundles("", enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationsEnabledForSpecialBundle_00001
 * @tc.desc: Test SetNotificationsEnabledForSpecialBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetNotificationsEnabledForSpecialBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    bool enabled = false;
    std::string deviceId = "deviceId";
    auto ret = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: IsAllowedNotify_00001
 * @tc.desc: Test IsAllowedNotify
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsAllowedNotify_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    bool allowed = false;
    auto ret = advancedNotificationService_->IsAllowedNotify(allowed);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsAllowedNotifyForBundle_00001
 * @tc.desc: Test IsAllowedNotifyForBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsAllowedNotifyForBundle_00001, Function | SmallTest | Level1)
{
    bool allowed = false;
    sptr<NotificationBundleOption> bundle = nullptr;
    auto ret = advancedNotificationService_->IsAllowedNotifyForBundle(bundle, allowed);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: TriggerLocalLiveView_00001
 * @tc.desc: Test TriggerLocalLiveView
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, TriggerLocalLiveView_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationButtonOption> buttonOption = nullptr;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->TriggerLocalLiveView(bundle, notificationId, buttonOption);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    ret = advancedNotificationService_->TriggerLocalLiveView(bundle, notificationId, buttonOption);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->TriggerLocalLiveView(bundle, notificationId, buttonOption);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveNotification_00001
 * @tc.desc: Test RemoveNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveNotification_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::string label = "label";
    int notificationId = 1;
    auto ret = advancedNotificationService_->RemoveNotification(bundle, notificationId, label, 0);

    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotifications_00001
 * @tc.desc: Test RemoveNotifications
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveNotifications_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    std::vector<std::string> keys;
    int removeReason = 1;
    auto ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotifications_00002
 * @tc.desc: Test RemoveNotifications
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveNotifications_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> keys;
    int removeReason = 1;

    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    req->SetOwnerUserId(1);
    req->SetOwnerBundleName(TEST_DEFUALT_BUNDLE);
    req->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(req, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    keys.emplace_back(record->notification->GetKey());

    ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: RemoveNotificationBySlot_00001
 * @tc.desc: Test RemoveNotificationBySlot
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveNotificationBySlot_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationSlot> slot = nullptr;
    auto ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveNotificationBySlot_00002
 * @tc.desc: Test RemoveNotificationBySlot
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveNotificationBySlot_00002, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetOwnerUserId(1);
    req->SetOwnerBundleName(TEST_DEFUALT_BUNDLE);
    req->SetNotificationId(1);
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    auto content = std::make_shared<NotificationContent>(multiLineContent);
    req->SetContent(content);
    auto record = advancedNotificationService_->MakeNotificationRecord(req, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    auto slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: NotificationSvrQueue_00001
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, NotificationSvrQueue_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

    auto ret = advancedNotificationService_->CancelAll();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->Delete("", 1);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->CancelGroup("group");
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->RemoveGroupByBundle(bundle, "group");
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool allowed = false;
    ret = advancedNotificationService_->IsSpecialUserAllowedNotify(1, allowed);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetNotificationsEnabledByUser(1, false);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    bool enabled = false;
    ret = advancedNotificationService_->GetEnabledForBundleSlot(bundle, slotType, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetBadgeNumber(1);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SubscribeLocalLiveView(nullptr, nullptr, true);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0100
 * @tc.desc: test SetDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetDistributedEnabledByBundle_0100, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0200
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetDistributedEnabledByBundle_0200, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0300
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetDistributedEnabledByBundle_0300, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(res, ERR_ANS_PERMISSION_DENIED);
}


/**
 * @tc.name: IsDistributedEnabledByBundle_0100
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0100, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0200
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0200, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode ret = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(ret, ERR_OK);
    bool enable = false;
    ret = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(enable, true);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0300
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0300, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0400
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0400, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: DuplicateMsgControl_00001
 * @tc.desc: Test DuplicateMsgControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DuplicateMsgControl_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);

    auto ret = advancedNotificationService_->DuplicateMsgControl(request);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: DuplicateMsgControl_00002
 * @tc.desc: Test DuplicateMsgControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DuplicateMsgControl_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test1");
    auto uniqueKey = request->GenerateUniqueKey();
    advancedNotificationService_->uniqueKeyList_.emplace_back(
        std::make_pair(std::chrono::system_clock::now(), uniqueKey));

    auto ret = advancedNotificationService_->DuplicateMsgControl(request);
    EXPECT_EQ(ret, (int)ERR_ANS_DUPLICATE_MSG);
}

/**
 * @tc.name: DuplicateMsgControl_00003
 * @tc.desc: Test DuplicateMsgControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DuplicateMsgControl_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");

    auto ret = advancedNotificationService_->DuplicateMsgControl(request);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 1);
}

/**
 * @tc.name: IsDuplicateMsg_00001
 * @tc.desc: Test IsDuplicateMsg
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDuplicateMsg_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");
    auto uniqueKey = request->GenerateUniqueKey();

    auto ret = advancedNotificationService_->IsDuplicateMsg(uniqueKey);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsDuplicateMsg_00002
 * @tc.desc: Test IsDuplicateMsg
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDuplicateMsg_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");
    auto uniqueKey = request->GenerateUniqueKey();
    advancedNotificationService_->uniqueKeyList_.emplace_back(
        std::make_pair(std::chrono::system_clock::now(), uniqueKey));

    auto ret = advancedNotificationService_->IsDuplicateMsg(uniqueKey);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: RemoveExpiredUniqueKey_00001
 * @tc.desc: Test RemoveExpiredUniqueKey
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveExpiredUniqueKey_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");
    auto uniqueKey = request->GenerateUniqueKey();
    advancedNotificationService_->uniqueKeyList_.emplace_back(
        std::make_pair(std::chrono::system_clock::now() - std::chrono::hours(24), uniqueKey));

    sleep(1);
    EXPECT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 1);
    advancedNotificationService_->RemoveExpiredUniqueKey();
    EXPECT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 0);
}

/*
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    ErrCode res = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * @tc.name: SetSmartReminderEnabled_0200
 * @tc.desc: test SetSmartReminderEnabled with parameters, expect errorCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetSmartReminderEnabled_0200, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    ErrCode res = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    EXPECT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: SetSmartReminderEnabled_0300
 * @tc.desc: test SetSmartReminderEnabled with parameters, expect errorCode ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetSmartReminderEnabled_0300, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    ErrCode res = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    EXPECT_EQ(res, ERR_ANS_PERMISSION_DENIED);
}


/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsSmartReminderEnabled_0200
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0200, TestSize.Level1)
{
    ErrCode ret = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    EXPECT_EQ(ret, ERR_OK);
    bool enable = false;
    ret = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType", enable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(enable, true);
}

/**
 * @tc.name: IsSmartReminderEnabled_0300
 * @tc.desc: test IsSmartReminderEnabled with parameters, expect errorCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0300, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: IsSmartReminderEnabled_0400
 * @tc.desc: test IsSmartReminderEnabled with parameters, expect errorCode ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0400, TestSize.Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: PublishRemoveDuplicateEvent_00001
 * @tc.desc: Test PublishRemoveDuplicateEvent
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PublishRemoveDuplicateEvent_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");
    request->SetNotificationId(1);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->PublishRemoveDuplicateEvent(record);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: PublishRemoveDuplicateEvent_00002
 * @tc.desc: Test PublishRemoveDuplicateEvent
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PublishRemoveDuplicateEvent_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record= nullptr;
    auto ret = advancedNotificationService_->PublishRemoveDuplicateEvent(record);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PublishRemoveDuplicateEvent_00003
 * @tc.desc: Test PublishRemoveDuplicateEvent
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PublishRemoveDuplicateEvent_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test2");
    request->SetNotificationId(1);
    request->SetIsAgentNotification(true);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->PublishRemoveDuplicateEvent(record);
    EXPECT_EQ(ret, (int)ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
