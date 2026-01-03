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
#include "notification_preferences.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
class AdvancedNotificationBadgeManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationBadgeManagerTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationBadgeManagerTest::SetUpTestCase() {}

void AdvancedNotificationBadgeManagerTest::TearDownTestCase() {}

void AdvancedNotificationBadgeManagerTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationBadgeManagerTest::TearDown()
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.number    : SetNotificationBadgeNum_0100
 * @tc.name      : SetNotificationBadgeNum_0100
 * @tc.desc      : Test SetNotificationBadgeNum function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetNotificationBadgeNum_0100, Function | MediumTest | Level1)
{
    int num = 2;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    auto ret = advancedNotificationService_->SetNotificationBadgeNum(num);
    EXPECT_EQ(ret, ERR_OK);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    ret = advancedNotificationService_->SetNotificationBadgeNum(num);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetShowBadgeEnabledForBundles_0100
 * @tc.name      : SetShowBadgeEnabledForBundles_0100
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetShowBadgeEnabledForBundles_0100, Function | MediumTest | Level1)
{
    std::map<sptr<NotificationBundleOption>, bool> bundleOptions;
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundles(bundleOptions);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number    : SetShowBadgeEnabledForBundles_0200
 * @tc.name      : SetShowBadgeEnabledForBundles_0200
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetShowBadgeEnabledForBundles_0200, Function | MediumTest | Level1)
{
    std::map<sptr<NotificationBundleOption>, bool> bundleOptions;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 100);
    bundleOptions[bundleOption] = true;
    MockIsSystemApp(true);
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundles(bundleOptions);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(bundleOption);
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
    ret = advancedNotificationService_->GetShowBadgeEnabledForBundles(bundles, bundleEnable);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : SetShowBadgeEnabledForBundles_0300
 * @tc.name      : SetShowBadgeEnabledForBundles_0300
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetShowBadgeEnabledForBundles_0300, Function | MediumTest | Level1)
{
    std::map<sptr<NotificationBundleOption>, bool> bundleOptions;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 100);
    bundleOptions[bundleOption] = true;
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundles(bundleOptions);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SetShowBadgeEnabledForBundles_0400
 * @tc.name      : SetShowBadgeEnabledForBundles_0400
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetShowBadgeEnabledForBundles_0400, Function | MediumTest | Level1)
{
    std::map<sptr<NotificationBundleOption>, bool> bundleOptions;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 100);
    bundleOptions[bundleOption] = true;
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundles(bundleOptions);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetShowBadgeEnabledForBundles_0500
 * @tc.name      : SetShowBadgeEnabledForBundles_0500
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, SetShowBadgeEnabledForBundles_0500, Function | MediumTest | Level1)
{
    std::map<sptr<NotificationBundleOption>, bool> bundleOptions;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 100);
    bundleOptions[bundleOption] = true;
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->SetShowBadgeEnabledForBundles(bundleOptions);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetShowBadgeEnabledForBundles_0100
 * @tc.name      : SetShowBadgeEnabledForBundles_0100
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, GetShowBadgeEnabledForBundles_0100, Function | MediumTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnable);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : GetShowBadgeEnabledForBundles_0200
 * @tc.name      : SetShowBadgeEnabledForBundles_0200
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, GetShowBadgeEnabledForBundles_0200, Function | MediumTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnable);
    EXPECT_EQ(ret, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : GetShowBadgeEnabledForBundles_0300
 * @tc.name      : SetShowBadgeEnabledForBundles_0300
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, GetShowBadgeEnabledForBundles_0300, Function | MediumTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnable);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetShowBadgeEnabledForBundles_0400
 * @tc.name      : SetShowBadgeEnabledForBundles_0400
 * @tc.desc      : Test SetShowBadgeEnabledForBundles function
 */
HWTEST_F(AdvancedNotificationBadgeManagerTest, GetShowBadgeEnabledForBundles_0400, Function | MediumTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnable);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}
}  // namespace Notification
}  // namespace OHOS
