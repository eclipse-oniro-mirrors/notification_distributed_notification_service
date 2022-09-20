/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "bundle_manager_helper.h"
#include "reminder_data_manager.h"
#undef private
#undef protected

#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "access_token_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class BundleManagerHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : BundleManagerHelperTest_00100
 * @tc.name      : ANS_GetBundleNameByUid_0100
 * @tc.desc      : Test GetBundleNameByUid function
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00100, Function | SmallTest | Level1)
{
    pid_t callingUid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    EXPECT_EQ(bundleManager->GetBundleNameByUid(callingUid), "bundleName");
}

/**
 * @tc.number    : BundleManagerHelperTest_00200
 * @tc.name      : ANS_IsSystemApp_0100
 * @tc.desc      : Test IsSystemApp function
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00200, Function | SmallTest | Level1)
{
    pid_t callingUid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    EXPECT_TRUE(bundleManager->IsSystemApp(callingUid));
}

/**
 * @tc.number    : BundleManagerHelperTest_00300
 * @tc.name      : CheckApiCompatibility
 * @tc.desc      : Test CheckApiCompatibility function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00300, Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.CheckApiCompatibility(bundleOption);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number    : BundleManagerHelperTest_00400
 * @tc.name      : GetBundleInfoByBundleName
 * @tc.desc      : Test GetBundleInfoByBundleName function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00400, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    AppExecFwk::BundleInfo bundleInfo;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.GetBundleInfoByBundleName(bundle, userId, bundleInfo);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number    : BundleManagerHelperTest_00500
 * @tc.name      : GetDefaultUidByBundleName
 * @tc.desc      : Test GetDefaultUidByBundleName function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00500, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    BundleManagerHelper bundleManagerHelper;
    int32_t result = bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId);
    EXPECT_EQ(result, 1000);
}

/**
 * @tc.number    : ReminderDataManagerTest_00200
 * @tc.name      : CheckReminderLimitExceededLocked
 * @tc.desc      : Test CheckReminderLimitExceededLocked function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00200, Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.CheckReminderLimitExceededLocked(bundleOption);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_00300
 * @tc.name      : FindReminderRequestLocked
 * @tc.desc      : Test FindReminderRequestLocked function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00300, Level1)
{
    int32_t reminderId = 1;
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.FindReminderRequestLocked(reminderId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00400
 * @tc.name      : FindReminderRequestLocked
 * @tc.desc      : Test FindReminderRequestLocked function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00400, Level1)
{
    int32_t reminderId = 1;
    std::string pkgName = "PkgName";
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.FindReminderRequestLocked(reminderId, pkgName);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00500
 * @tc.name      : FindNotificationBundleOption
 * @tc.desc      : Test FindNotificationBundleOption function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00500, Level1)
{
    int32_t reminderId = 1;
    ReminderDataManager reminderDataManager;
    sptr<NotificationBundleOption> result = reminderDataManager.FindNotificationBundleOption(reminderId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00700
 * @tc.name      : GetInstance
 * @tc.desc      : Test GetInstance function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00700, Level1)
{
    ReminderDataManager reminderDataManager;
    std::shared_ptr<ReminderDataManager> result = reminderDataManager.GetInstance();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_00900
 * @tc.name      : ShouldAlert
 * @tc.desc      : Test ShouldAlert function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_00900, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.ShouldAlert(reminder);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_01200
 * @tc.name      : GetRecentReminderLocked
 * @tc.desc      : Test GetRecentReminderLocked function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_01200, Level1)
{
    ReminderDataManager reminderDataManager;
    sptr<ReminderRequest> result = reminderDataManager.GetRecentReminderLocked();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number    : ReminderDataManagerTest_01400
 * @tc.name      : IsAllowedNotify
 * @tc.desc      : Test IsAllowedNotify function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_01400, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.IsAllowedNotify(reminder);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ReminderDataManagerTest_01500
 * @tc.name      : IsReminderAgentReady
 * @tc.desc      : Test IsReminderAgentReady function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_01500, Level1)
{
    ReminderDataManager reminderDataManager;
    bool result = reminderDataManager.IsReminderAgentReady();
    EXPECT_EQ(result, true);
}

/**
 * @tc.number    : ReminderDataManagerTest_01700
 * @tc.name      : GetSoundUri
 * @tc.desc      : Test GetSoundUri function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_01700, Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderDataManager reminderDataManager;
    std::string result = reminderDataManager.GetSoundUri(reminder);
    EXPECT_EQ(result, "//system/etc/Light.ogg");
}

/**
 * @tc.number    : ReminderDataManagerTest_01100
 * @tc.name      : Dump
 * @tc.desc      : Test Dump function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, ReminderDataManagerTest_01100, Level1)
{
    ReminderDataManager reminderDataManager;
    std::string result = reminderDataManager.Dump();
    EXPECT_EQ(result.size(), 68);
}

/**
 * @tc.number    : AccessTokenHelperTest_00100
 * @tc.name      : IsSystemHap
 * @tc.desc      : Test IsSystemHap function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, AccessTokenHelperTest_00100, Level1)
{
    AccessTokenHelper accessTokenHelper;
    bool result = accessTokenHelper.IsSystemHap();
    EXPECT_EQ(result, false);
}
}  // namespace Notification
}  // namespace OHOS
