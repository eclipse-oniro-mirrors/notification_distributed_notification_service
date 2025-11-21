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
#include <thread>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "advanced_datashare_helper.h"
#include "notification_bluetooth_helper.h"
#include "notification_check_request.h"
#include "notification_constant.h"
#include "notification_preferences.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"
#include "mock_bluetooth.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {

class AdvancedNotificationExtensionSubscriptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationExtensionSubscriptionTest::advancedNotificationService_ =
    nullptr;

void AdvancedNotificationExtensionSubscriptionTest::SetUpTestCase() {}

void AdvancedNotificationExtensionSubscriptionTest::TearDownTestCase() {}

void AdvancedNotificationExtensionSubscriptionTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();

    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationExtensionSubscriptionTest::TearDown()
{
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: NotificationExtensionSubscribe_0100
 * @tc.desc: Test NotificationExtensionSubscribe without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0100,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0200
 * @tc.desc: Test NotificationExtensionSubscribe with empty infos.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0200,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0300
 * @tc.desc: Test NotificationExtensionSubscribe with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0300,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0400
 * @tc.desc: Test NotificationExtensionSubscribe without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0400,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0500
 * @tc.desc: Test NotificationExtensionSubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0500,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_NOT_IMPL_EXTENSIONABILITY);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0100
 * @tc.desc: Test NotificationExtensionUnsubscribe without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0100,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0200
 * @tc.desc: Test NotificationExtensionUnsubscribe with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0200,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0300
 * @tc.desc: Test NotificationExtensionUnsubscribe without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0300,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0400
 * @tc.desc: Test NotificationExtensionUnsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0400,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetSubscribeInfo_0100
 * @tc.desc: Test GetSubscribeInfo without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetSubscribeInfo_0200
 * @tc.desc: Test GetSubscribeInfo with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: GetSubscribeInfo_0300
 * @tc.desc: Test GetSubscribeInfo without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSubscribeInfo_0400
 * @tc.desc: Test GetSubscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00001
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00100, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : IsUserGranted_00200
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00200, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.number    : IsUserGranted_00300
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00300, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : IsUserGranted_00400
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00400, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(new (std::nothrow) NotificationRequest(),
        bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : GetUserGrantedState_0100
 * @tc.name      : GetUserGrantedState
 * @tc.desc      : Test GetUserGrantedState
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0100, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : GetUserGrantedState_0200
 * @tc.name      : GetUserGrantedState_NoPermission
 * @tc.desc      : Test GetUserGrantedState without permission
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0200, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    
    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetUserGrantedState_0300
 * @tc.name      : GetUserGrantedState_InvalidBundle
 * @tc.desc      : Test GetUserGrantedState with invalid bundle
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0300, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = nullptr;
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    
    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedState_0400
 * @tc.name      : GetUserGrantedState_NullQueue
 * @tc.desc      : Test GetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedState_0500
 * @tc.name      : GetUserGrantedState ERR_ANS_INVALID_BUNDLE_OPTION
 * @tc.desc      : Test GetUserGrantedState ERR_ANS_INVALID_BUNDLE_OPTION case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(invalidBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedState_0600
 * @tc.name      : GetUserGrantedState_Success
 * @tc.desc      : Test GetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0600, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedState_0100
 * @tc.name      : SetUserGrantedState_NonSystemApp
 * @tc.desc      : Test SetUserGrantedState for non-system app
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0100, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SetUserGrantedState_0200
 * @tc.name      : SetUserGrantedState_NoPermission
 * @tc.desc      : Test SetUserGrantedState without permission
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0200, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    
    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetUserGrantedState_0300
 * @tc.name      : SetUserGrantedState_InvalidBundle
 * @tc.desc      : Test SetUserGrantedState with invalid bundle
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0300, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = nullptr;
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    
    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedState_0400
 * @tc.name      : SetUserGrantedState_NullQueue
 * @tc.desc      : Test SetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedState_0500
 * @tc.name      : SetUserGrantedState ERR_ANS_INVALID_BUNDLE_OPTION
 * @tc.desc      : Test SetUserGrantedState ERR_ANS_INVALID_BUNDLE_OPTION case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(invalidBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedState_0600
 * @tc.name      : SetUserGrantedState_Success
 * @tc.desc      : Test SetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0600, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0100
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0100, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, extensionBundles);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(nullptr, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(invalidBundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0200
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0200, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0300
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0300, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0100
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0100, Function | SmallTest
    | Level1)
{
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0200
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0200, Function | SmallTest
    | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0300
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0300, Function | SmallTest
    | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0100
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    auto ret = advancedNotificationService_->SetUserGrantedBundleState(nullptr, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0200
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0300
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0400
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> invalidextensionBundles = {
        new NotificationBundleOption("invalidBundle", -1),
    };
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(
        invalidBundle, invalidextensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, invalidextensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0500
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0200, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0100
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0100, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0200
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0200, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_ANS_NOT_IMPL_EXTENSIONABILITY);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0300
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0300, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0100
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.push_back(sptr<NotificationExtensionSubscriptionInfo>(
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)));
    ErrCode ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundleOption, infos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0200
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.push_back(sptr<NotificationExtensionSubscriptionInfo>(
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)));
    advancedNotificationService_->supportHfp_ = true;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos);
    EXPECT_FALSE(ret);
    advancedNotificationService_->supportHfp_ = false;
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0300
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        nullptr,
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::BLUETOOTH),
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    infos[2]->SetHfp(true);
    advancedNotificationService_->supportHfp_ = true;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos);
    EXPECT_FALSE(ret);
    advancedNotificationService_->supportHfp_ = false;
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0400
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    advancedNotificationService_->supportHfp_ = true;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos);
    EXPECT_TRUE(ret);
    advancedNotificationService_->supportHfp_ = false;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0500
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->supportHfp_ = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos);
    EXPECT_TRUE(ret);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0100
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0100, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles;
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_TRUE(bundles.empty());
    ASSERT_TRUE(extensionBundleInfos.empty());
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0200
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0200, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles = {
        new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)
    };
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_TRUE(bundles.empty());
    ASSERT_TRUE(extensionBundleInfos.empty());
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0300
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0300, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles = {
        new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)
    };
    MockIsVerfyPermisson(true);
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_TRUE(bundles.empty());
    ASSERT_TRUE(extensionBundleInfos.empty());
    MockIsVerfyPermisson(false);
}
/**
 * @tc.number    : CheckExtensionServiceCondition_0400
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0400, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0400", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_TRUE(bundles.empty());
    ASSERT_TRUE(extensionBundleInfos.empty());
    MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0500
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0500, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0500", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_FALSE(bundles.empty());
    ASSERT_TRUE(extensionBundleInfos.empty());
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0600
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0600, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0600", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->CheckExtensionServiceCondition(extensionBundleInfos, bundles);
    ASSERT_FALSE(bundles.empty());
    ASSERT_FALSE(extensionBundleInfos.empty());
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : FilterPermissionBundles_0100
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    MockIsVerfyPermisson(false);
    advancedNotificationService_->FilterPermissionBundles(bundles);
    ASSERT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterPermissionBundles_0200
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0200, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    MockIsVerfyPermisson(true);
    advancedNotificationService_->FilterPermissionBundles(bundles);
    ASSERT_FALSE(bundles.empty());
}

/**
 * @tc.number    : FilterGrantedBundles_0100
 * @tc.name      : FilterGrantedBundles
 * @tc.desc      : Test FilterGrantedBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterGrantedBundles_0100, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    
    auto ret = notificationPreferences.SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(bundleOption);
    advancedNotificationService_->FilterGrantedBundles(bundles);
    ASSERT_FALSE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0100
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0100,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles);
    ASSERT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0200
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName.0200", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ASSERT_EQ(ret, ERR_OK);

    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles);
    ASSERT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0300
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0300,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName.0300", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ASSERT_EQ(ret, ERR_OK);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);

    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles);
    ASSERT_FALSE(bundles.empty());
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckBluetoothConditions_0100
 * @tc.name      : CheckBluetoothConditions
 * @tc.desc      : Test CheckBluetoothConditions case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConditions_0100, Function | SmallTest | Level1)
{
    bool ret = NotificationBluetoothHelper::GetInstance().CheckBluetoothConditions("test_addr");
    ASSERT_FALSE(ret);
}

/**
 * @tc.number    : HasExtensionSubscriptionStateChanged_0100
 * @tc.name      : HasExtensionSubscriptionStateChanged
 * @tc.desc      : Test HasExtensionSubscriptionStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HasExtensionSubscriptionStateChanged_0100,
    Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    auto ret = notificationPreferences.SetExtensionSubscriptionEnabled(bundle,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    ASSERT_EQ(ret, ERR_OK);
    bool ret2 = advancedNotificationService_->HasExtensionSubscriptionStateChanged(bundle, true);
    ASSERT_FALSE(ret2);

    ret2 = advancedNotificationService_->HasExtensionSubscriptionStateChanged(nullptr, true);
    ASSERT_TRUE(ret2);
}

/**
 * @tc.number    : EnsureExtensionServiceLoadedAndSubscribed_0100
 * @tc.name      : EnsureExtensionServiceLoadedAndSubscribed
 * @tc.desc      : Test EnsureExtensionServiceLoadedAndSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureExtensionServiceLoadedAndSubscribed_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ASSERT_TRUE(advancedNotificationService_->EnsureExtensionServiceLoadedAndSubscribed(bundle));
    advancedNotificationService_->UnSubscribeExtensionService(bundle);
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : EnsureExtensionServiceLoadedAndSubscribed_0200
 * @tc.name      : EnsureExtensionServiceLoadedAndSubscribed
 * @tc.desc      : Test EnsureExtensionServiceLoadedAndSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureExtensionServiceLoadedAndSubscribed_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    ASSERT_TRUE(advancedNotificationService_->EnsureExtensionServiceLoadedAndSubscribed(bundle, subscribeBundles));
    advancedNotificationService_->UnSubscribeExtensionService(bundle);
}

/**
 * @tc.number    : EnsureExtensionServiceLoadedAndSubscribed_0300
 * @tc.name      : EnsureExtensionServiceLoadedAndSubscribed
 * @tc.desc      : Test EnsureExtensionServiceLoadedAndSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureExtensionServiceLoadedAndSubscribed_0300,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_FALSE(advancedNotificationService_->EnsureExtensionServiceLoadedAndSubscribed(bundle, subscribeBundles));
}

/**
 * @tc.number    : EnsureExtensionServiceLoadedAndSubscribed_0400
 * @tc.name      : EnsureExtensionServiceLoadedAndSubscribed
 * @tc.desc      : Test EnsureExtensionServiceLoadedAndSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureExtensionServiceLoadedAndSubscribed_0400,
    Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle.Name.0400", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(
        bundleOption, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_TRUE(advancedNotificationService_->EnsureExtensionServiceLoadedAndSubscribed(bundleOption, bundles));
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
    advancedNotificationService_->UnSubscribeExtensionService(bundleOption);
}

#else
/**
 * @tc.number    : EnsureExtensionServiceLoadedAndSubscribed_0200
 * @tc.name      : EnsureExtensionServiceLoadedAndSubscribed
 * @tc.desc      : Test EnsureExtensionServiceLoadedAndSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureExtensionServiceLoadedAndSubscribed_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    ASSERT_TRUE(advancedNotificationService_->EnsureExtensionServiceLoadedAndSubscribed(bundle, subscribeBundles));
}
#endif

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : ShutdownExtensionServiceAndUnSubscribed_0100
 * @tc.name      : ShutdownExtensionServiceAndUnSubscribed
 * @tc.desc      : Test ShutdownExtensionServiceAndUnSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionServiceAndUnSubscribed_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_FALSE(advancedNotificationService_->ShutdownExtensionServiceAndUnSubscribed(bundle));
}

/**
 * @tc.number    : ShutdownExtensionServiceAndUnSubscribed_0200
 * @tc.name      : ShutdownExtensionServiceAndUnSubscribed
 * @tc.desc      : Test ShutdownExtensionServiceAndUnSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionServiceAndUnSubscribed_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    ASSERT_TRUE(advancedNotificationService_->ShutdownExtensionServiceAndUnSubscribed(bundle));
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}
#else
/**
 * @tc.number    : ShutdownExtensionServiceAndUnSubscribed_0100
 * @tc.name      : ShutdownExtensionServiceAndUnSubscribed
 * @tc.desc      : Test ShutdownExtensionServiceAndUnSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionServiceAndUnSubscribed_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ASSERT_TRUE(advancedNotificationService_->ShutdownExtensionServiceAndUnSubscribed(bundle));
}
#endif

/**
 * @tc.number    : HandleBundleInstall_0100
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->HandleBundleInstall(nullptr);
    ASSERT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleInstall_0200
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->HandleBundleInstall(bundle);
    ASSERT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleInstall_0300
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->HandleBundleInstall(bundle);
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0100
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID));
    advancedNotificationService_->HandleBundleUpdate(nullptr);
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUpdate_0200
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    ASSERT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUpdate_0300
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0400
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0400,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUninstall_0100
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID));
    advancedNotificationService_->HandleBundleUninstall(nullptr);
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUninstall_0200
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUninstall(bundle);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUninstall_0300
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("bundleName1", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("bundleName2", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle1);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle2);
    advancedNotificationService_->HandleBundleUninstall(bundle1);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : OnHfpDeviceConnectChanged_0100
 * @tc.name      : OnHfpDeviceConnectChanged
 * @tc.desc      : Test OnHfpDeviceConnectChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnHfpDeviceConnectChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    Bluetooth::BluetoothRemoteDevice device;
    advancedNotificationService_->OnHfpDeviceConnectChanged(
        device, static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : OnBluetoothStateChanged_0100
 * @tc.name      : OnBluetoothStateChanged
 * @tc.desc      : Test OnBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnBluetoothStateChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    advancedNotificationService_->OnBluetoothStateChanged(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : OnBluetoothPairedStatusChanged_0100
 * @tc.name      : OnBluetoothPairedStatusChanged
 * @tc.desc      : Test OnBluetoothPairedStatusChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnBluetoothPairedStatusChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    Bluetooth::BluetoothRemoteDevice device;
    advancedNotificationService_->OnBluetoothPairedStatusChanged(
        device, static_cast<int32_t>(OHOS::Bluetooth::PAIR_PAIRED));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0100
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0200
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessHfpDeviceStateChange.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0300
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessHfpDeviceStateChange.0300", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0100
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0200
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0300
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessBluetoothStateChanged.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundle };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundle, bundles);
    ASSERT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundle,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    ASSERT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
#else
    ASSERT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
#endif
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0100
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0100,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    ASSERT_TRUE(bundles.empty());
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0200
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0200,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    for (size_t i = 0; i < bundles.size(); ++i) {
        ASSERT_EQ(bundles[i]->GetBundleName(), "test_bundle");
        ASSERT_EQ(bundles[i]->GetUid(), NON_SYSTEM_APP_UID);
    }
    MockIsNeedHapModuleInfos(false);
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0300
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0300,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockGetCloneAppIndexes(true);
    MockGetCloneBundleInfo(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    for (size_t i = 0; i < bundles.size(); ++i) {
        ASSERT_EQ(bundles[i]->GetBundleName(), "test_bundle");
        ASSERT_EQ(bundles[i]->GetUid(), NON_SYSTEM_APP_UID);
    }
    MockIsNeedHapModuleInfos(false);
    MockGetCloneAppIndexes(false);
    MockGetCloneBundleInfo(false);
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
}

/**
 * @tc.number    : isExtensionServiceExist_0100
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    ASSERT_FALSE(advancedNotificationService_->isExtensionServiceExist());
}

/**
 * @tc.number    : isExtensionServiceExist_0200
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_FALSE(advancedNotificationService_->isExtensionServiceExist());
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : isExtensionServiceExist_0300
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ =
        std::make_shared<NotificationLoadUtils>("does_not_exist.z.so");
    ASSERT_FALSE(advancedNotificationService_->isExtensionServiceExist());

    advancedNotificationService_->notificationExtensionHandler_ =
        std::make_shared<NotificationLoadUtils>("libans_extension_service.z.so");
    ASSERT_TRUE(advancedNotificationService_->isExtensionServiceExist());
}
#endif

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : LoadExtensionService_0100
 * @tc.name      : LoadExtensionService
 * @tc.desc      : Test LoadExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, LoadExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    ASSERT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
    ASSERT_NE(advancedNotificationService_->notificationExtensionHandler_, nullptr);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}

/**
 * @tc.number    : LoadExtensionService_0200
 * @tc.name      : LoadExtensionService
 * @tc.desc      : Test LoadExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, LoadExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    ASSERT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
    ASSERT_NE(advancedNotificationService_->notificationExtensionHandler_, nullptr);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}
#else
/**
 * @tc.number    : LoadExtensionService_0100
 * @tc.name      : LoadExtensionService
 * @tc.desc      : Test LoadExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, LoadExtensionService_0100,
    Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
}
#endif

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : SubscribeExtensionService_0100
 * @tc.name      : SubscribeExtensionService
 * @tc.desc      : Test SubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ASSERT_EQ(advancedNotificationService_->SubscribeExtensionService(bundle, bundles), -1);
}

/**
 * @tc.number    : SubscribeExtensionService_0200
 * @tc.name      : SubscribeExtensionService
 * @tc.desc      : Test SubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ASSERT_EQ(advancedNotificationService_->SubscribeExtensionService(bundle, bundles), 0);
    advancedNotificationService_->UnSubscribeExtensionService(bundle);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}
#else
/**
 * @tc.number    : SubscribeExtensionService_0100
 * @tc.name      : SubscribeExtensionService
 * @tc.desc      : Test SubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ASSERT_EQ(advancedNotificationService_->SubscribeExtensionService(bundle, bundles), 0);
}
#endif

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : UnSubscribeExtensionService_0100
 * @tc.name      : UnSubscribeExtensionService
 * @tc.desc      : Test UnSubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, UnSubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->UnSubscribeExtensionService(bundle), -1);
}

/**
 * @tc.number    : UnSubscribeExtensionService_0200
 * @tc.name      : UnSubscribeExtensionService
 * @tc.desc      : Test UnSubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, UnSubscribeExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->UnSubscribeExtensionService(bundle), 0);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}
#else
/**
 * @tc.number    : UnSubscribeExtensionService_0100
 * @tc.name      : UnSubscribeExtensionService
 * @tc.desc      : Test UnSubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, UnSubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->UnSubscribeExtensionService(bundle), 0);
}
#endif

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : ShutdownExtensionService_0100
 * @tc.name      : ShutdownExtensionService
 * @tc.desc      : Test ShutdownExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->ShutdownExtensionService(), -1);
}

/**
 * @tc.number    : ShutdownExtensionService_0200
 * @tc.name      : ShutdownExtensionService
 * @tc.desc      : Test ShutdownExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    ASSERT_EQ(advancedNotificationService_->ShutdownExtensionService(), 0);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}
#else
/**
 * @tc.number    : ShutdownExtensionService_0100
 * @tc.name      : ShutdownExtensionService
 * @tc.desc      : Test ShutdownExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionService_0100,
    Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->ShutdownExtensionService(), 0);
}
#endif

/**
 * @tc.number    : RegisterBluetoothAccessObserver_0100
 * @tc.name      : RegisterBluetoothAccessObserver
 * @tc.desc      : Test RegisterBluetoothAccessObserver case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, RegisterBluetoothAccessObserver_0100, Function | SmallTest | Level1)
{
    auto &helper = NotificationBluetoothHelper::GetInstance();
    helper.bluetoothAccessObserver_ = nullptr;
    helper.isBluetoothObserverRegistered_.store(false);
    helper.RegisterBluetoothAccessObserver();
    auto firstPtr = helper.bluetoothAccessObserver_;
    ASSERT_NE(firstPtr, nullptr);
    ASSERT_TRUE(helper.isBluetoothObserverRegistered_.load());
    helper.RegisterBluetoothAccessObserver();
    ASSERT_EQ(firstPtr, helper.bluetoothAccessObserver_);
    ASSERT_TRUE(helper.isBluetoothObserverRegistered_.load());
    helper.isBluetoothObserverRegistered_.store(true);
    helper.bluetoothAccessObserver_ = nullptr;
    helper.RegisterBluetoothAccessObserver();
    ASSERT_NE(helper.bluetoothAccessObserver_, nullptr);
}

/**
 * @tc.number    : OnConnectionStateChanged_0100
 * @tc.name      : OnConnectionStateChanged
 * @tc.desc      : Test OnConnectionStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnConnectionStateChanged_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    HfpStateObserver observer;
    OHOS::Bluetooth::BluetoothRemoteDevice device("00:11:22:33:44:55", OHOS::Bluetooth::BT_TRANSPORT_NONE);
    observer.OnConnectionStateChanged(device, 1, 0);
    auto singleton = AdvancedNotificationService::GetInstance();
    ASSERT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
    EXPECT_TRUE(singleton->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : OnStateChanged_0100
 * @tc.name      : OnStateChanged
 * @tc.desc      : Test OnStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnStateChanged_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    BluetoothAccessObserver observer;
    observer.OnStateChanged(1, 2);
    auto singleton = AdvancedNotificationService::GetInstance();
    ASSERT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
}

/**
 * @tc.number    : OnPairStatusChanged_0100
 * @tc.name      : OnPairStatusChanged
 * @tc.desc      : Test OnPairStatusChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnPairStatusChanged_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    BluetoothPairedDeviceObserver observer;
    OHOS::Bluetooth::BluetoothRemoteDevice device("00:11:22:33:44:55", OHOS::Bluetooth::BT_TRANSPORT_NONE);
    observer.OnPairStatusChanged(device, 3, 0);
    auto singleton = AdvancedNotificationService::GetInstance();
    ASSERT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
}

/**
 * @tc.number    : GetCloneBundleList_0100
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, -1);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    EXPECT_FALSE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
}

/**
 * @tc.number    : GetCloneBundleList_0200
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    EXPECT_FALSE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
}

/**
 * @tc.number    : GetCloneBundleList_0300
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    MockGetCloneAppIndexes(true);
    EXPECT_TRUE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
    MockGetCloneAppIndexes(false);
}

/**
 * @tc.number    : GetCloneBundleList_0400
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    MockGetCloneAppIndexes(true);
    MockGetCloneBundleInfo(true);
    EXPECT_TRUE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_FALSE(cloneBundleList.empty());
    MockGetCloneAppIndexes(false);
    MockGetCloneBundleInfo(false);
}
}
}