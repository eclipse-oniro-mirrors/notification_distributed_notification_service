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
#include "bundle_manager_helper.h"
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
    BundleManagerHelper::GetInstance()->bundleMgr_ =  nullptr;
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERROR_INTERNAL_ERROR);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
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
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0200, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_OK);
}
}
}