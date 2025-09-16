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
#include "notification_check_request.h"
#include "notification_constant.h"

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
 * @tc.number    : AdvancedNotificationServiceTest_00002
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
 * @tc.number    : AdvancedNotificationServiceTest_00003
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
 * @tc.number    : AdvancedNotificationServiceTest_00004
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
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00005
 * @tc.name      : GetUserGrantedState_NullQueue
 * @tc.desc      : Test GetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    
    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00006
 * @tc.name      : GetUserGrantedState_Success
 * @tc.desc      : Test GetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00007
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
 * @tc.number    : AdvancedNotificationServiceTest_00008
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
 * @tc.number    : AdvancedNotificationServiceTest_00009
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
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00010
 * @tc.name      : SetUserGrantedState_NullQueue
 * @tc.desc      : Test SetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    
    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00011
 * @tc.name      : SetUserGrantedState_Success
 * @tc.desc      : Test SetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
}
}
}