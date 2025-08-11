/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "advanced_datashare_helper.h"
#include "ability_manager_errors.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "ans_ut_constant.h"
#include "ans_dialog_host_client.h"
#include "mock_parameters.h"
#include "mock_push_callback_stub.h"
#include "mock_ipc_skeleton.h"
#include "bool_wrapper.h"
#include "string_wrapper.h"
#include "want_params.h"
#include "int_wrapper.h"
#include "os_account_manager_helper.h"

extern void MockIsOsAccountExists(bool exists);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsAtomicServiceByFullTokenID(bool isAtomicService);
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
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->CancelAll("");
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
    ASSERT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: Publish_00002
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00002, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption("bundleName", 1), true), (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERROR_USER_NOT_EXIST);
}

/**
 * @tc.name: Publish_00007
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00007, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetOwnerUid(1);
    request->SetIsAgentNotification(true);
    request->SetIsDoNotDisturbByPassed(true);
    MockIsOsAccountExists(true);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: Publish_00008
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00008, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetOwnerUid(1);
    request->SetCreatorUid(1);
    request->SetCreatorUserId(100);
    request->SetIsAgentNotification(true);
    MockIsOsAccountExists(true);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: Publish_00009
 * @tc.desc: Test Publish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Publish_00009, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string label = "";
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    MockIsAtomicServiceByFullTokenID(true);

    auto ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
    ret = advancedNotificationService_->PublishNotificationForIndirectProxy(request);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsAtomicServiceByFullTokenID(false);
}

/**
 * @tc.name: DeleteByBundle_00001
 * @tc.desc: Test DeleteByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteByBundle_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    auto ret = advancedNotificationService_->DeleteByBundle(bundleOption);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.name: DeleteByBundle_00004
 * @tc.desc: Test DeleteByBundle,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_OK
 *  3. Subsystem (Native token) and non-system app -> return ERR_OK
 *  4. Subsystem (Native token) and system app -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteByBundle_00004, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->DeleteByBundle(bundle);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
  
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->DeleteByBundle(bundle);
    ASSERT_EQ(result, ERR_OK);
 
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->DeleteByBundle(bundle);
    ASSERT_EQ(result, ERR_OK);
 
    MockIsSystemApp(true);
    result = advancedNotificationService_->DeleteByBundle(bundle);
    ASSERT_EQ(result, ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveDistributedNotifications_00001
 * @tc.desc: delete distributed notificaitons test permission and param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveDistributedNotifications_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    
    MockIsSystemApp(false);
    std::vector<std::string> hashcodes;
    auto ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, 99, 99);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, 99, 99);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, 99, 99);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}


/**
 * @tc.name: RemoveDistributedNotifications_00002
 * @tc.desc: delete distributed notificaitons test permission and param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveDistributedNotifications_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<std::string> hashcodes;
    auto ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, NotificationConstant::DistributedDeleteType::ALL, 99);
    ASSERT_EQ(ret, (int)ERR_OK);

    ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, NotificationConstant::DistributedDeleteType::SLOT, 99);
    ASSERT_EQ(ret, (int)ERR_OK);

    ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99, NotificationConstant::DistributedDeleteType::HASHCODES, 99);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: RemoveDistributedNotifications_00003
 * @tc.desc: delete distributed notificaitons test permission and param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveDistributedNotifications_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetLabel("123");
    sptr<Notification> notification1(new (std::nothrow) Notification(request1));
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request1;
    record1->notification = notification1;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);

    std::vector<std::string> hashcodes;
    hashcodes.push_back(notification->GetKey());
    auto ret = advancedNotificationService_->RemoveDistributedNotifications(
        hashcodes, 99);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: RemoveDistributedNotifications_00004
 * @tc.desc: delete distributed notificaitons test permission and param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveDistributedNotifications_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<Notification> notification1(new (std::nothrow) Notification(request1));
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request1;
    record1->notification = notification1;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);

    std::vector<std::string> hashcodes;
    hashcodes.push_back(notification->GetKey());
    auto ret = advancedNotificationService_->RemoveDistributedNotifications(
        NotificationConstant::SlotType::LIVE_VIEW, 99,
        NotificationConstant::DistributedDeleteType::SLOT);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: RemoveDistributedNotifications_00005
 * @tc.desc: delete distributed notificaitons test permission and param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveDistributedNotifications_00005, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request1->SetDistributedCollaborate(true);
    sptr<Notification> notification1(new (std::nothrow) Notification(request1));
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request1;
    record1->notification = notification1;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);

    std::vector<std::string> hashcodes;
    hashcodes.push_back(notification->GetKey());
    auto ret = advancedNotificationService_->RemoveDistributedNotifications(
        NotificationConstant::SlotType::LIVE_VIEW, 99,
        NotificationConstant::DistributedDeleteType::EXCLUDE_ONE_SLOT);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: RemoveAllDistributedNotifications_00001
 * @tc.desc: delete ALL distributed notificaitons
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveAllDistributedNotifications_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<Notification> notification1(new (std::nothrow) Notification(request1));
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request1;
    record1->notification = notification1;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);

    std::vector<std::string> hashcodes;
    hashcodes.push_back(notification->GetKey());
    auto ret = advancedNotificationService_->RemoveAllDistributedNotifications(99);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: ExecuteDeleteDistributedNotification_00001
 * @tc.desc: delete ALL distributed notificaitons
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, ExecuteDeleteDistributedNotification_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    std::shared_ptr<NotificationRecord> record;
    auto res = advancedNotificationService_->ExecuteDeleteDistributedNotification(
        record, notifications, 99);
    ASSERT_FALSE(res);
    ASSERT_EQ(notifications.size(), 0);

    record = std::make_shared<NotificationRecord>();
    res = advancedNotificationService_->ExecuteDeleteDistributedNotification(
        record, notifications, 99);
    ASSERT_FALSE(res);
    ASSERT_EQ(notifications.size(), 0);

    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    
    res = advancedNotificationService_->ExecuteDeleteDistributedNotification(
        record, notifications, 99);
    ASSERT_TRUE(res);
    ASSERT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: IsDistributedNotification_00001
 * @tc.desc: delete ALL distributed notificaitons
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedNotification_00001, Function | SmallTest | Level1)
{
    auto res = advancedNotificationService_->IsDistributedNotification(nullptr);
    ASSERT_FALSE(res);

    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetDistributedCollaborate(true);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    res = advancedNotificationService_->IsDistributedNotification(request);
    ASSERT_TRUE(res);

    request->SetDistributedCollaborate(false);
    res = advancedNotificationService_->IsDistributedNotification(request);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: DeleteAll_00002
 * @tc.desc: Test DeleteAll,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_OK
 *  3. Subsystem (Native token) and non-system app -> return ERR_OK
 *  4. Subsystem (Native token) and system app -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteAll_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->DeleteAll();
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->DeleteAll();
    ASSERT_EQ(result, ERR_OK);
 
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->DeleteAll();
    ASSERT_EQ(result, ERR_OK);
 
    MockIsSystemApp(true);
    result = advancedNotificationService_->DeleteAll();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DeleteAll_00003
 * @tc.desc: Test DeleteAll when GetCurrentActiveUserId faild, except is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DeleteAll_00003, Function | SmallTest | Level1)
{
    MockGetOsAccountLocalIdFromUid(false, 1);
    auto ret = advancedNotificationService_->DeleteAll();
    ASSERT_EQ(ret, (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);

    bool enabled = false;
    ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enabled = false;
    ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetShowBadgeEnabledForBundle_00003
 * @tc.desc: Test SetShowBadgeEnabledForBundle,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_OK
 *  3. Subsystem (Native token) and non-system app -> return ERR_OK
 *  4. Subsystem (Native token) and system app -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetShowBadgeEnabledForBundle_00003, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    bool enabled = true;
    auto result = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
    result = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
  
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
  
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(enabled, true);
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
    ASSERT_EQ(ret, (int)ERR_OK);

    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    ASSERT_EQ(ret, (int)ERROR_INTERNAL_ERROR);
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
    ASSERT_EQ(ret, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    ASSERT_EQ(ret, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);

    auto bundle = advancedNotificationService_->GenerateBundleOption();
    NotificationPreferences::GetInstance()->SetHasPoppedDialog(bundle, true);

    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);

    NotificationPreferences::GetInstance()->SetHasPoppedDialog(bundle, false);
    ret = advancedNotificationService_->RequestEnableNotification(deviceId, client, callerToken);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RequestEnableNotification_00004
 * @tc.desc: Test RequestEnableNotification,two parameters,except is ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RequestEnableNotification_00004, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName1";
    int32_t uid = 1;
    auto ret = advancedNotificationService_->RequestEnableNotification(bundleName, uid);
    ASSERT_EQ(ret, (int)ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: RequestEnableNotification_00005
 * @tc.desc: Test RequestEnableNotification,
 *  without permission, except is ERR_ANS_PERMISSION_DENIED
 *  with permission, zyt, except is ERR_ANS_NOT_ALLOWED
 *  with permission, easy, except is ERR_ANS_NOT_ALLOWED
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RequestEnableNotification_00005, Function | SmallTest | Level1)
{
    std::string bundleName = "com.zhuoyi.appstore.lite";
    int32_t uid = 1;
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->RequestEnableNotification(bundleName, uid);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RequestEnableNotification(bundleName, uid);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);
    bundleName = "com.easy.abroad";
    ret = advancedNotificationService_->RequestEnableNotification(bundleName, uid);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);
}

/**
 * @tc.name: CommonRequestEnableNotification_00001
 * @tc.desc: Test CommonRequestEnableNotification, when bundleOption is nullptr, except is ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CommonRequestEnableNotification_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool innerLake = true;
    auto ret = advancedNotificationService_->
        CommonRequestEnableNotification(deviceId, nullptr, nullptr, bundleOption, innerLake, false);
    ASSERT_EQ(ret, (int)ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: CommonRequestEnableNotification_00002
 * @tc.desc: Test CommonRequestEnableNotification, when bundleOption is not nullptr,
 *          IsAllowedNotifySelf is true, RequestEnableNotificationDailog falid,
 *          except is ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CommonRequestEnableNotification_00002, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    bool innerLake = true;
    auto ret = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true);
    ASSERT_EQ(ret, (int)ERR_OK);
    ret = advancedNotificationService_->
        CommonRequestEnableNotification(deviceId, nullptr, nullptr, bundle, innerLake, false);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CommonRequestEnableNotification_00003
 * @tc.desc: Test CommonRequestEnableNotification, when bundleOption is not nullptr,
 *          IsAllowedNotifySelf is false, except is ERROR_INTERNAL_ERROR
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CommonRequestEnableNotification_00003, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    bool innerLake = true;
    auto ret = advancedNotificationService_->
        CommonRequestEnableNotification(deviceId, nullptr, nullptr, bundle, innerLake, false);
    ASSERT_EQ(ret, (int)ERROR_INTERNAL_ERROR);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles_00002
 * @tc.desc: Test SetNotificationsEnabledForAllBundles,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_OK
 *  3. Subsystem (Native token) and non-system app -> return ERR_OK
 *  4. Subsystem (Native token) and system app -> return ERR_OK
 *  5. GetcurrentActiveUserId faild -> return ERR_ANS_GET_ACTIVE_USER_FAILED
 *  6. GetcurrentActiveUserId success -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetNotificationsEnabledForAllBundles_00002, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    bool enabled = true;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_OK);
  
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_OK);
 
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_OK);

    MockQueryForgroundOsAccountId(false, 1);
    result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_ANS_GET_ACTIVE_USER_FAILED);

    MockQueryForgroundOsAccountId(true, 1);
    result = advancedNotificationService_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    ASSERT_EQ(result, ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetNotificationsEnabledForSpecialBundle_00002
 * @tc.desc: Test SetNotificationsEnabledForSpecialBundle,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_OK
 *  3. Subsystem (Native token) and non-system app -> return ERR_OK
 *  4. Subsystem (Native token) and system app -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetNotificationsEnabledForSpecialBundle_00002, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    bool enabled = true;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
  
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SetNotificationsEnabledForSpecialBundle_00003
 * @tc.desc: Test SetNotificationsEnabledForSpecialBundle,
 *  1. callingUid is not ans uid, and without permission -> return ERR_ANS_PERMISSION_DENIED
 *  2. callingUid is not ans uid, and with permission -> return ERR_OK
 *  3. callingUid is ans uid, and without permission -> return ERR_OK
 *  4. callingUid is ans uid, and with permission -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetNotificationsEnabledForSpecialBundle_00003, Function | SmallTest | Level1)
{
    std::string deviceId = "";
    bool enabled = true;
    int32_t ansUid = 5523;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(false);
    IPCSkeleton::SetCallingUid(12345);
    auto result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
    
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingUid(12345);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
    
    MockIsVerfyPermisson(false);
    IPCSkeleton::SetCallingUid(ansUid);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
   
    MockIsSystemApp(true);
    result = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(deviceId, bundle, enabled);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsAllowedNotify_00001
 * @tc.desc: Test IsAllowedNotify, when notificationSvrQueue_ is nullptr
 *  without permission
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_ANS_PERMISSION_DENIED
 *  3. Subsystem (Native token) and non-system app -> return ERR_ANS_PERMISSION_DENIED
 *  4. Subsystem (Native token) and system app -> return ERR_ANS_PERMISSION_DENIED
 *  with permission
 *  5. GetcurrentActiveUserId faild -> return ERR_ANS_GET_ACTIVE_USER_FAILED
 *  6. GetcurrentActiveUserId success -> return ERR_ANS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsAllowedNotify_00001, Function | SmallTest | Level1)
{
    bool enabled = true;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
    
    MockIsSystemApp(true);
    result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
   
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
  
    MockIsSystemApp(true);
    result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    MockQueryForgroundOsAccountId(false, 1);
    result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_GET_ACTIVE_USER_FAILED);
 
    MockQueryForgroundOsAccountId(true, 1);
    result = advancedNotificationService_->IsAllowedNotify(enabled);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    ret = advancedNotificationService_->TriggerLocalLiveView(bundle, notificationId, buttonOption);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->TriggerLocalLiveView(bundle, notificationId, buttonOption);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RemoveNotifications(keys, removeReason);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_OK);
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
    auto ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot,
        NotificationConstant::DEFAULT_REASON_DELETE);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot,
        NotificationConstant::DEFAULT_REASON_DELETE);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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

    ret = advancedNotificationService_->RemoveNotificationBySlot(bundle, slot,
        NotificationConstant::DEFAULT_REASON_DELETE);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: NotificationSvrQueue_00001
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, NotificationSvrQueue_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

    auto ret = advancedNotificationService_->CancelAll("");
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->Delete("", 1);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->CancelGroup("group", "");
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->RemoveGroupByBundle(bundle, "group");
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool allowed = false;
    ret = advancedNotificationService_->IsSpecialUserAllowedNotify(1, allowed);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetNotificationsEnabledByUser(1, false);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetBadgeNumber(1, "");
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SubscribeLocalLiveView(nullptr, nullptr, true);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0100
 * @tc.desc: test SetDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetDistributedEnabledByBundle_0100, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode res = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    ASSERT_EQ(res, ERR_OK);
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
    ASSERT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(res, ERR_ANS_PERMISSION_DENIED);
}


/**
 * @tc.name: IsDistributedEnabledByBundle_0100
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0100, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0200
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDistributedEnabledByBundle_0200, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("bundleName", 1));
    std::string deviceType = "testDeviceType";

    ErrCode ret = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    ASSERT_EQ(ret, ERR_OK);
    bool enable = false;
    ret = advancedNotificationService_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(enable, true);
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
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
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
    ASSERT_EQ(ret, (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_DUPLICATE_MSG);
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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 1);
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
    auto ret = advancedNotificationService_->IsDuplicateMsg(advancedNotificationService_->uniqueKeyList_, uniqueKey);
    ASSERT_EQ(ret, false);
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
    auto ret = advancedNotificationService_->IsDuplicateMsg(advancedNotificationService_->uniqueKeyList_, uniqueKey);
    ASSERT_EQ(ret, true);
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
    ASSERT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 1);
    advancedNotificationService_->RemoveExpiredUniqueKey();
    ASSERT_EQ(advancedNotificationService_->uniqueKeyList_.size(), 0);
}

/**
 * @tc.name: RemoveExpiredDistributedUniqueKey_00001
 * @tc.desc: Test RemoveExpiredDistributedUniqueKey
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveExpiredDistributedUniqueKey_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test3");
    auto distributedUniqueKey = request->GenerateDistributedUniqueKey();
    advancedNotificationService_->distributedUniqueKeyList_.emplace_back(
        std::make_pair(std::chrono::system_clock::now() - std::chrono::hours(24), distributedUniqueKey));

    sleep(1);
    ASSERT_EQ(advancedNotificationService_->distributedUniqueKeyList_.size(), 1);
    advancedNotificationService_->RemoveExpiredDistributedUniqueKey();
    ASSERT_EQ(advancedNotificationService_->distributedUniqueKeyList_.size(), 0);
}

/**
 * @tc.name: RemoveExpiredLocalUniqueKey_00001
 * @tc.desc: Test RemoveExpiredLocalUniqueKey
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveExpiredLocalUniqueKey_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetAppMessageId("test4");
    auto localUniqueKey = request->GenerateDistributedUniqueKey();
    advancedNotificationService_->localUniqueKeyList_.emplace_back(
        std::make_pair(std::chrono::system_clock::now() - std::chrono::hours(24), localUniqueKey));

    sleep(1);
    ASSERT_EQ(advancedNotificationService_->localUniqueKeyList_.size(), 1);
    advancedNotificationService_->RemoveExpiredLocalUniqueKey();
    ASSERT_EQ(advancedNotificationService_->localUniqueKeyList_.size(), 0);
}

/*
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ErrCode res = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    ASSERT_EQ(res, ERR_OK);
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
    ASSERT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(res, ERR_ANS_PERMISSION_DENIED);
}


/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    bool enable = true;
    ErrCode result = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType1111", enable);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: IsSmartReminderEnabled_0200
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsSmartReminderEnabled_0200, TestSize.Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->SetSmartReminderEnabled("testDeviceType", true);
    ASSERT_EQ(ret, ERR_OK);
    bool enable = false;
    ret = advancedNotificationService_->IsSmartReminderEnabled("testDeviceType", enable);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(enable, true);
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
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
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
    ASSERT_EQ(ret, (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: CanPopEnableNotificationDialog_001
 * @tc.desc: Test CanPopEnableNotificationDialog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CanPopEnableNotificationDialog_001, Function | SmallTest | Level1)
{
    sptr<IAnsDialogCallback> callback = nullptr;
    bool canPop = false;
    std::string bundleName = "";
    ErrCode result = advancedNotificationService_->CanPopEnableNotificationDialog(callback, canPop, bundleName);
    ASSERT_EQ(result, ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: IsDisableNotification_001
 * @tc.desc: Test IsDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotification_001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = advancedNotificationService_->IsDisableNotification(bundleName);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: IsDisableNotification_002
 * @tc.desc: Test IsDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotification_002, Function | SmallTest | Level1)
{
    bool defaultPolicy = system::GetBoolParameter("persist.edm.notification_disable", false);
    if (!defaultPolicy) {
        system::SetBoolParameter("persist.edm.notification_disable", true);
    }
    std::string bundleName = "";
    bool result = advancedNotificationService_->IsDisableNotification(bundleName);
    ASSERT_TRUE(result);
    system::SetBoolParameter("persist.edm.notification_disable", defaultPolicy);
}

/**
 * @tc.name: IsNeedToControllerByDisableNotification_001
 * @tc.desc: Test IsNeedToControllerByDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsNeedToControllerByDisableNotification_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    bool result = advancedNotificationService_->IsNeedToControllerByDisableNotification(request);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsNeedToControllerByDisableNotification_002
 * @tc.desc: Test IsNeedToControllerByDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsNeedToControllerByDisableNotification_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;
    bool result = advancedNotificationService_->IsNeedToControllerByDisableNotification(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PrePublishRequest_00001
 * @tc.desc: Test PrePublishRequest
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PrePublishRequest_00001, Function | SmallTest | Level1)
{
    MockIsOsAccountExists(false);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetReceiverUserId(-99);
    ASSERT_EQ(advancedNotificationService_->PrePublishRequest(request), (int)ERROR_USER_NOT_EXIST);
    MockIsOsAccountExists(true);
    sptr<NotificationRequest> request1 = new NotificationRequest();
    request1->SetCreatorUid(0);
    request1->SetReceiverUserId(100);
    ASSERT_EQ(advancedNotificationService_->PrePublishRequest(request1), (int)ERR_ANS_INVALID_UID);
    sptr<NotificationRequest> request2 = new NotificationRequest();
    request2->SetDeliveryTime(-1);
    request2->SetReceiverUserId(100);
    request2->SetCreatorUid(1);
    ASSERT_EQ(advancedNotificationService_->PrePublishRequest(request2), (int)ERR_OK);
}

/**
 * @tc.name: CollaboratePublish_00001
 * @tc.desc: Test CollaboratePublish
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CollaboratePublish_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::string label = "";
    request->SetAppMessageId("test2");
    request->SetNotificationId(1);
    request->SetIsAgentNotification(true);
    request->SetDistributedCollaborate(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: CollaboratePublish_00002
 * @tc.desc: Test CollaboratePublish,
 *  common live view without permisson, except is ERR_ANS_PERMISSION_DENIED
 *  common live view with permisson, except is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CollaboratePublish_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> notificationContent = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(notificationContent);
    std::string label = "";
    request->SetAppMessageId("test1");
    request->SetNotificationId(1);
    request->SetIsAgentNotification(true);
    request->SetDistributedCollaborate(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->Publish(label, request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: CollaboratePublish_00003
 * @tc.desc: Test permission of CollaboratePublish,
 *  Non-subsystem (HAP token), without permisson, except is ERR_ANS_PERMISSION_DENIED
 *  Non-subsystem (HAP token), with permisson, except is ERR_ANS_PERMISSION_DENIED
 *  Subsystem (Native token), without permisson, except is ERR_ANS_PERMISSION_DENIED
 *  Subsystem (Native token), with permisson, except is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CollaboratePublish_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->CollaboratePublish(request);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->CollaboratePublish(request);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->CollaboratePublish(request);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->CollaboratePublish(request);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: PublishNotificationForIndirectProxy_00001
 * @tc.desc: Test PublishNotificationForIndirectProxy,
 *  request is nullptr, return is ERR_ANS_INVALID_PARAM
 *  request is valid, uid is invalid, return is ERR_ANS_INVALID_UID
 *  sound is empty, return is ERR_OK
 *  sound is not empty, return is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PublishNotificationForIndirectProxy_00001, Function | SmallTest | Level1)
{
    auto ret = advancedNotificationService_->PublishNotificationForIndirectProxy(nullptr);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ret = advancedNotificationService_->PublishNotificationForIndirectProxy(request);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_UID);
    request->SetCreatorUid(1);
    ret = advancedNotificationService_->PublishNotificationForIndirectProxy(request);
    ASSERT_EQ(ret, (int)ERR_OK);
    request->SetSound("sound");
    request->SetCreatorBundleName("creatorname");
    request->SetAppInstanceKey("key");
    ret = advancedNotificationService_->PublishNotificationForIndirectProxy(request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: PublishNotificationForIndirectProxy_00002
 * @tc.desc: Test PublishNotificationForIndirectProxy,
 *  request is valid, creator uid is 0, PrePublishRequest faild, except is ERR_ANS_INVALID_UID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, PublishNotificationForIndirectProxy_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorUid(0);
    auto ret = advancedNotificationService_->PublishNotificationForIndirectProxy(request);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: CancelAsBundle_00001
 * @tc.desc: Test CancelAsBundle,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  3. Subsystem (Native token) and non-system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  4. Subsystem (Native token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CancelAsBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", 1);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->CancelAsBundle(bundle, 1, 1);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->CancelAsBundle(bundle, 1, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->CancelAsBundle(bundle, 1, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockIsSystemApp(true);
    result = advancedNotificationService_->CancelAsBundle(bundle, 1, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: CancelAsBundle_00002
 * @tc.desc: Test CancelAsBundle,
 *  bundleOption is valid, userId is -2, checkUserIdParams faild, except is ERR_ANS_INVALID_UID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CancelAsBundle_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", 1);
    MockIsOsAccountExists(false);
    auto result = advancedNotificationService_->CancelAsBundle(bundle, 1, -2);
    ASSERT_EQ(result, (int)ERROR_USER_NOT_EXIST);
}

/**
 * @tc.name: CancelAsBundle_00003
 * @tc.desc: Test CancelAsBundle,
 *  uid is 0, except is ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CancelAsBundle_00003, Function | SmallTest | Level1)
{
    MockIsOsAccountExists(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", 0);
    auto result = advancedNotificationService_->CancelAsBundle(bundle, 1);
    ASSERT_EQ(result, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: CancelAsBundleWithAgent_00001
 * @tc.desc: Test CancelAsBundleWithAgent,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  3. Subsystem (Native token) and non-system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  4. Subsystem (Native token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  5. Subsystem (Native token) and system app, uid < 0 -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CancelAsBundleWithAgent_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", 1);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->CancelAsBundleWithAgent(bundle, 1);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->CancelAsBundleWithAgent(bundle, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->CancelAsBundleWithAgent(bundle, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockIsSystemApp(true);
    result = advancedNotificationService_->CancelAsBundleWithAgent(bundle, 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    bundle->SetUid(-1);
    result = advancedNotificationService_->CancelAsBundleWithAgent(bundle, 1);
    ASSERT_EQ(result, ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: Delete_00001
 * @tc.desc: Test Delete,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  3. Subsystem (Native token) and non-system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 *  4. Subsystem (Native token) and system app -> return ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, Delete_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto result = advancedNotificationService_->Delete("key", 1);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
 
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    result = advancedNotificationService_->Delete("key", 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    result = advancedNotificationService_->Delete("key", 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockIsSystemApp(true);
    result = advancedNotificationService_->Delete("key", 1);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: RemoveEnableNotificationDialog_00001
 * @tc.desc: Test RemoveEnableNotificationDialog, except is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveEnableNotificationDialog_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto ret = advancedNotificationService_->RemoveEnableNotificationDialog();
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: QueryContactByProfileId_00001
 * @tc.desc: Test QueryContactByProfileId, except is -1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, QueryContactByProfileId_00001, Function | SmallTest | Level1)
{
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    bool isDataShareReady = true;
    datashareHelper->SetIsDataShareReady(isDataShareReady);
    std::string phoneNumber = "12345678";
    std::string policy = "5";
    int32_t userId = 100;
    auto ret = advancedNotificationService_->QueryContactByProfileId(phoneNumber, policy, userId);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: SetDistributedEnabledBySlot_00001
 * @tc.desc: Test SetDistributedEnabledBySlot, except is -1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetDistributedEnabledBySlot_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "testdeviceType";
    bool enabled = true;
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetTargetDeviceStatus_00001
 * @tc.desc: Test SetTargetDeviceStatus, deviceType is empty, except is ERR_ANS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetTargetDeviceStatus_00001, Function | SmallTest | Level1)
{
    std::string deviceType = "";
    uint32_t status = 0;
    std::string deviceId = "";
    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, deviceId);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetTargetDeviceStatus_00001
 * @tc.desc: Test GetTargetDeviceStatus, deviceType is empty, except is ERR_ANS_INVALID_PARAM
 * @tc.desc: Test GetTargetDeviceStatus, deviceType is not empty, status == inputStatus
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, GetTargetDeviceStatus_00001, Function | SmallTest | Level1)
{
    std::string deviceType = "";
    int32_t inputStatus = 1;
    int32_t status = 0;
    auto ret = advancedNotificationService_->GetTargetDeviceStatus(deviceType, status);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
    uint32_t controlFlag = 0;
    deviceType = "testdeviceType";
    std::string deviceId = "";
    ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, inputStatus, deviceId);
    ASSERT_EQ(ret, ERR_OK);
    ret = advancedNotificationService_->GetTargetDeviceStatus(deviceType, status);
    ASSERT_EQ(status, inputStatus);
}

/**
 * @tc.name: ClearAllNotificationGroupInfo_00001
 * @tc.desc: Test ClearAllNotificationGroupInfo, deviceType is not empty, except is ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, ClearAllNotificationGroupInfo_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    std::string localSwitch = "false";
    advancedNotificationService_->aggregateLocalSwitch_ = true;
    advancedNotificationService_->ClearAllNotificationGroupInfo(localSwitch);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_EQ(advancedNotificationService_->aggregateLocalSwitch_, false);
}

/**
 * @tc.name: RemoveAllNotificationsByBundleName_00001
 * @tc.desc: Test RemoveAllNotificationsByBundleName, except is notificationList_ == 1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, RemoveAllNotificationsByBundleName_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    record1->bundleOption = bundle;
    advancedNotificationService_->notificationList_.push_back(record1);
    auto record2 = nullptr;
    advancedNotificationService_->notificationList_.push_back(record2);
    std::string bundleName = TEST_DEFUALT_BUNDLE;
    int32_t reason = 0;
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);
    auto ret = advancedNotificationService_->RemoveAllNotificationsByBundleName(bundleName, reason);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: DistributeOperation_00001
 * @tc.desc: Test DistributeOperation,
 *  without hashcode, return is ERR_ANS_INVALID_PARAM
 *  without permisson, return is ERR_ANS_PERMISSION_DENIED
 *  DistributeOperationParamCheck faild, except is ERR_ANS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, DistributeOperation_00001, Function | SmallTest | Level1)
{
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    sptr<IAnsOperationCallback> callback = nullptr;
    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
    std::string hashCode = "123456";
    operationInfo->SetHashCode(hashCode);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetBadgeNumberForDhByBundle_00001
 * @tc.desc: Test SetBadgeNumberForDhByBundle,
 *  1. Parameter validation:
 *      - bundleOption is null -> return ERR_ANS_INVALID_PARAM
 *      - bundleName is empty -> return ERR_ANS_INVALID_PARAM
 *      - uid <= 0 -> return ERR_ANS_INVALID_PARAM
 *      - badgeNumber < 0 -> return ERR_ANS_INVALID_PARAM
 *  2. Permission validation:
 *      - Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *      - Subsystem (Native token) and non-system app -> ERR_OK
 *      - Non-subsystem (HAP token) and system app -> ERR_OK
 *      - Subsystem (Native token) and system app -> ERR_OK
 *  3. Success path:
 *      -All valid conditions (non-null bundleOption, valid bundleName, uid>0, badgeNumber>0, valid permissions)
 *       ->return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetBadgeNumberForDhByBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    auto ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, -1);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    bundle = new NotificationBundleOption("", 0);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, -1);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    bundle->SetBundleName("bundle");
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, -1);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    bundle->SetUid(12345);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, -1);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 1);
    ASSERT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 1);
    ASSERT_EQ(ret, ERR_OK);

    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 1);
    ASSERT_EQ(ret, ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 1);
    ASSERT_EQ(ret, ERR_OK);

    bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 1);
    ASSERT_EQ(ret, ERR_OK);

    ret = advancedNotificationService_->SetBadgeNumberForDhByBundle(bundle, 0);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetHashCodeRule_00001
 * @tc.desc: Test SetHashCodeRule,
 *  1. Non-subsystem (HAP token) and non-system app -> return ERR_ANS_NON_SYSTEM_APP
 *  2. Non-subsystem (HAP token) and system app with invalid UID -> return ERR_ANS_PERMISSION_DENIED
 *  3. Non-subsystem (HAP token) and system app with valid UID -> return ERR_OK
 *  4. Subsystem (Native token) with invalid UID -> return ERR_ANS_PERMISSION_DENIED
 *  5. Subsystem (Native token) with valid UID -> return ERR_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, SetHashCodeRule_00001, Function | SmallTest | Level1)
{
    int32_t avseesaionPid = 6700;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    IPCSkeleton::SetCallingUid(12345);
    auto result = advancedNotificationService_->SetHashCodeRule(1);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    IPCSkeleton::SetCallingUid(12345);
    result = advancedNotificationService_->SetHashCodeRule(1);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    IPCSkeleton::SetCallingUid(avseesaionPid);
    result = advancedNotificationService_->SetHashCodeRule(1);
    ASSERT_EQ(result, ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    IPCSkeleton::SetCallingUid(12345);
    result = advancedNotificationService_->SetHashCodeRule(1);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    IPCSkeleton::SetCallingUid(avseesaionPid);
    result = advancedNotificationService_->SetHashCodeRule(1);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CollaborateFilter_00001
 * @tc.desc: Test CollaborateFilter
 * 1.extendInfo is null return ok
 * 2.notification_collaboration_check is false, return ok
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CollaborateFilter_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_OK);

    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("test", AAFwk::String::Box("test"));
    request->SetExtendInfo(extendInfo);

    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_OK);

    extendInfo->SetParam("notification_collaboration_check", AAFwk::Boolean::Box(false));
    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_OK);

    extendInfo->SetParam("notification_collaboration_check", AAFwk::Boolean::Box(true));
    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);
}

/**
 * @tc.name: CollaborateFilter_00002
 * @tc.desc: Test CollaborateFilter
 * 1.DistributedAuthStatus closed, return ERR_ANS_NOT_ALLOWED
 * 2.liveView:DistributedAuthStatus open, liveView distributed switch close, return ERR_ANS_NOT_ALLOWED
 * 3.notification:DistributedAuthStatus open, distributed switch close, return ERR_ANS_NOT_ALLOWED
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, CollaborateFilter_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("notification_collaboration_check", AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);

    std::string deviceType = "deviceType";
    std::string deviceId = "deviceId";
    std::string localType = "localType";
    int32_t userId = 100;
    extendInfo->SetParam("notification_collaboration_deviceType", AAFwk::String::Box(deviceType));
    extendInfo->SetParam("notification_collaboration_deviceId", AAFwk::String::Box(deviceId));
    extendInfo->SetParam("notification_collaboration_localType", AAFwk::String::Box(localType));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    NotificationPreferences::GetInstance()->SetDistributedAuthStatus(deviceType, deviceId, userId, true);
    
    NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(
        NotificationConstant::SlotType::LIVE_VIEW, localType, true);
    auto ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_OK);
    
    NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(
        NotificationConstant::SlotType::LIVE_VIEW, localType, false);
    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);

    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    NotificationPreferences::GetInstance()->SetDistributedEnabled(
        localType, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_OK);

    NotificationPreferences::GetInstance()->SetDistributedEnabled(
        localType, NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    ret = advancedNotificationService_->CollaborateFilter(request);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_ALLOWED);

    NotificationPreferences::GetInstance()->SetDistributedAuthStatus(deviceType, deviceId, userId, false);
}

/**
 * @tc.name: ClearSlotTypeData_00001
 * @tc.desc: Test ClearSlotTypeData
 * 1.sourceType == CLEAR_SLOT_FROM_AVSEESAION condation
 * 2.sourceType == CLEAR_SLOT_FROM_RSS condation
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, ClearSlotTypeData_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    int32_t callingUid = 0;
    int32_t sourceType = 0;
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 0);

    sourceType = 1;
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 1);

    callingUid = 6700;
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 1);

    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 1);

    sourceType = 2;
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 2);

    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 2);

    request->SetCreatorUid(3051);
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 2);

    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    advancedNotificationService_->ClearSlotTypeData(request, callingUid, sourceType);
    ASSERT_EQ(sourceType, 2);
}

/**
 * @tc.name: IsEnableNotificationByKioskAppTrustList_001
 * @tc.desc: Test IsEnableNotificationByKioskAppTrustList
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsEnableNotificationByKioskAppTrustList_001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = advancedNotificationService_->IsEnableNotificationByKioskAppTrustList(bundleName);
    EXPECT_FALSE(result);
    bundleName = "com.test.example";
    NotificationPreferences::GetInstance()->preferencesInfo_.kioskAppTrustList_.emplace_back(bundleName);
    result = advancedNotificationService_->IsEnableNotificationByKioskAppTrustList(bundleName);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsDisableNotificationByKiosk_001
 * @tc.desc: Test IsDisableNotificationByKiosk
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotificationByKiosk_001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = advancedNotificationService_->IsDisableNotificationByKiosk(bundleName);
    EXPECT_FALSE(result);
    NotificationPreferences::GetInstance()->SetKioskModeStatus(true);
    result = advancedNotificationService_->IsDisableNotificationByKiosk(bundleName);
    EXPECT_TRUE(result);
    bundleName = "com.test.example";
    NotificationPreferences::GetInstance()->preferencesInfo_.kioskAppTrustList_.emplace_back(bundleName);
    result = advancedNotificationService_->IsDisableNotificationByKiosk(bundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsDisableNotificationForSaByKiosk_001
 * @tc.desc: Test IsDisableNotificationForSaByKiosk
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotificationForSaByKiosk_001, Function | SmallTest | Level1)
{
    std::string bundleName = "com.test.example";
    EXPECT_FALSE(advancedNotificationService_->IsDisableNotificationForSaByKiosk(bundleName, true));

    bundleName = "";
    EXPECT_FALSE(advancedNotificationService_->IsDisableNotificationForSaByKiosk(bundleName, false));
}

/**
 * @tc.name: IsDisableNotificationForSaByKiosk_002
 * @tc.desc: Test IsDisableNotificationForSaByKiosk
 * @tc.type: FUNC
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotificationForSaByKiosk_002, Function | SmallTest | Level1)
{
    std::string bundleName = "com.test.example";
    NotificationPreferences::GetInstance()->isKioskMode_ = true;
    NotificationPreferences::GetInstance()->preferencesInfo_.kioskAppTrustList_.clear();

    EXPECT_TRUE(advancedNotificationService_->IsDisableNotificationForSaByKiosk(bundleName, false));
}

/**
 * @tc.name: IsDisableNotification_003
 * @tc.desc: Test IsDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotification_003, Function | SmallTest | Level1)
{
    bool defaultPolicy = system::GetBoolParameter("persist.edm.notification_disable", false);
    if (defaultPolicy) {
        system::SetBoolParameter("persist.edm.notification_disable", false);
    }
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId), ERR_OK);
    std::string bundleName = "com.testDisableNotification.example";
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList = {bundleName};
    notificationDisable.SetDisabled(true);
    notificationDisable.SetBundleList(bundleList);
    notificationDisable.SetUserId(userId);
    sptr<NotificationDisable> notificationDisablePtr = new (std::nothrow) NotificationDisable(notificationDisable);
    NotificationPreferences::GetInstance()->preferencesInfo_.SetDisableNotificationInfo(notificationDisablePtr);
    bool result = advancedNotificationService_->IsDisableNotification(bundleName);
    EXPECT_TRUE(result);
    NotificationPreferences::GetInstance()->preferencesInfo_.userDisableNotificationInfo_.clear();
    system::SetBoolParameter("persist.edm.notification_disable", defaultPolicy);
}

/**
 * @tc.name: IsDisableNotification_004
 * @tc.desc: Test IsDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotification_004, Function | SmallTest | Level1)
{
    bool defaultPolicy = system::GetBoolParameter("persist.edm.notification_disable", false);
    if (defaultPolicy) {
        system::SetBoolParameter("persist.edm.notification_disable", false);
    }
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId), ERR_OK);
    std::string bundleName = "com.testDisableNotification.example";
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList = {bundleName};
    notificationDisable.SetDisabled(false);
    notificationDisable.SetBundleList(bundleList);
    notificationDisable.SetUserId(userId);
    sptr<NotificationDisable> notificationDisablePtr = new (std::nothrow) NotificationDisable(notificationDisable);
    NotificationPreferences::GetInstance()->preferencesInfo_.SetDisableNotificationInfo(notificationDisablePtr);
    bool result = advancedNotificationService_->IsDisableNotification(bundleName);
    EXPECT_FALSE(result);
    NotificationPreferences::GetInstance()->preferencesInfo_.userDisableNotificationInfo_.clear();
    system::SetBoolParameter("persist.edm.notification_disable", defaultPolicy);
}

/**
 * @tc.name: IsDisableNotification_005
 * @tc.desc: Test IsDisableNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsPublishServiceTest, IsDisableNotification_005, Function | SmallTest | Level1)
{
    bool defaultPolicy = system::GetBoolParameter("persist.edm.notification_disable", false);
    if (defaultPolicy) {
        system::SetBoolParameter("persist.edm.notification_disable", false);
    }
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId), ERR_OK);
    std::string bundleName = "com.testDisableNotification.example";
    NotificationDisable notificationDisable;
    notificationDisable.SetDisabled(true);
    notificationDisable.SetUserId(userId);
    sptr<NotificationDisable> notificationDisablePtr = new (std::nothrow) NotificationDisable(notificationDisable);
    NotificationPreferences::GetInstance()->preferencesInfo_.SetDisableNotificationInfo(notificationDisablePtr);
    bool result = advancedNotificationService_->IsDisableNotification(bundleName);
    EXPECT_FALSE(result);
    NotificationPreferences::GetInstance()->preferencesInfo_.userDisableNotificationInfo_.clear();
    system::SetBoolParameter("persist.edm.notification_disable", defaultPolicy);
}

/*
 * @tc.name: AtomicServicePublish_0100
 * @tc.desc: test PublishNotification with common liveView.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsPublishServiceTest, AtomicServicePublish_0200, Function | MediumTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> request = new NotificationRequest(1000);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetIsAgentNotification(true);
    request->SetOwnerBundleName("test.com");
    request->SetOwnerUserId(-1);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("autoServiceInstallStatus", AAFwk::Integer::Box(0));
    request->SetExtendInfo(extendInfo);
    auto ret = advancedNotificationService_->Publish("", request);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}
}  // namespace Notification
}  // namespace OHOS
