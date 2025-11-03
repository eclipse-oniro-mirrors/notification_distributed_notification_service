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
 * @tc.number    : RefreshExtensionSubscriptionBundlesFromConfig_0100
 * @tc.name      : RefreshExtensionSubscriptionBundlesFromConfig
 * @tc.desc      : Test RefreshExtensionSubscriptionBundlesFromConfig case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, RefreshExtensionSubscriptionBundlesFromConfig_0100,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode ret = advancedNotificationService_->RefreshExtensionSubscriptionBundlesFromConfig(nullptr, bundles);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("", NON_SYSTEM_APP_UID);
    ret = advancedNotificationService_->RefreshExtensionSubscriptionBundlesFromConfig(bundle, bundles);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RefreshExtensionSubscriptionBundlesFromConfig_0200
 * @tc.name      : RefreshExtensionSubscriptionBundlesFromConfig
 * @tc.desc      : Test RefreshExtensionSubscriptionBundlesFromConfig case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, RefreshExtensionSubscriptionBundlesFromConfig_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode ret = advancedNotificationService_->RefreshExtensionSubscriptionBundlesFromConfig(bundle, bundles);
    ASSERT_EQ(ret, ERR_OK);
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
}
}