/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"
#define private public
#define protected public
#include "notification_clone_disturb_service.h"
#include "notification_preferences_info.h"
#include "notification_do_not_disturb_profile.h"
#include "ans_inner_errors.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "mock/mock_notification_clone_util.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::SetArgPointee;
using ::testing::Return;
using ::testing::DoAll;
using namespace OHOS;
using namespace Notification;

// Test suite class
class NotificationCloneDisturbTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        notificationCloneDisturb = new NotificationCloneDisturb();
    }

    void TearDown() override
    {
        // Clean up resources
        delete notificationCloneDisturb;
    }

    NotificationCloneDisturb* notificationCloneDisturb;
};

/**
 * @tc.name: OnBackUp_00001
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnBackUp_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    int32_t userId = 100;
    auto advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    
    MockNotificationCloneUtil* mockCloneUtil = new MockNotificationCloneUtil();
    EXPECT_CALL(*mockCloneUtil, GetActiveUserId()).WillOnce(Return(userId));

    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    
    ErrCode result = notificationCloneDisturb->OnBackup(jsonObject);
    notificationCloneDisturb->OnRestore(jsonObject);
    EXPECT_EQ(result, ERR_OK);
}


/**
 * @tc.name: OnRestore_00001
 * @tc.desc: Test clone OnRestore jsonObject is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nullptr;
    notificationCloneDisturb->OnRestore(jsonObject);
    EXPECT_EQ(jsonObject, nullptr);
}

/**
 * @tc.name: GetProfileUid_Test_001
 * @tc.desc: Test that the function sets the UID from uidMap when the key exists in uidMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, GetProfileUid_Test_001, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::map<std::string, int32_t> uidMap;
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> exitBunldleList;
    std::vector<NotificationBundleOption> notExitBunldleList;

    // Create a bundle with a known key
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);
    std::string key = "com.example.app1";
    uidMap[key] = 12345;

    trustList.push_back(bundle);

    notificationCloneDisturb->GetProfileUid(userId, uidMap, trustList, exitBunldleList, notExitBunldleList);

    EXPECT_EQ(exitBunldleList.size(), 1);
    EXPECT_EQ(notExitBunldleList.size(), 0);
}

/**
 * @tc.name: GetProfileUid_Test_002
 * @tc.desc: Test that the function sets the UID from uidMap when the key exists in uidMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, GetProfileUid_Test_002, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::map<std::string, int32_t> uidMap;
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> exitBunldleList;
    std::vector<NotificationBundleOption> notExitBunldleList;

    // Create a bundle with an unknown key
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    trustList.push_back(bundle);

    MockNotificationCloneUtil* mockCloneUtil = new MockNotificationCloneUtil();
    EXPECT_CALL(*mockCloneUtil, GetBundleUid(_, _, _)).WillOnce(Return(54321));

    notificationCloneDisturb->GetProfileUid(userId, uidMap, trustList, exitBunldleList, notExitBunldleList);

    EXPECT_EQ(exitBunldleList.size(), 0);
    EXPECT_EQ(notExitBunldleList.size(), 1);
}

/**
 * @tc.name: GetProfileUid_Test_003
 * @tc.desc: Test that the function sets the UID from uidMap when the key exists in uidMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, GetProfileUid_Test_003, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::map<std::string, int32_t> uidMap;
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> exitBunldleList;
    std::vector<NotificationBundleOption> notExitBunldleList;

    // Create a bundle
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    trustList.push_back(bundle);

    MockNotificationCloneUtil* mockCloneUtil = new MockNotificationCloneUtil();
    EXPECT_CALL(*mockCloneUtil, GetBundleUid(_, _, _)).WillOnce(Return(-1));

    notificationCloneDisturb->GetProfileUid(userId, uidMap, trustList, exitBunldleList, notExitBunldleList);

    EXPECT_EQ(exitBunldleList.size(), 0);
    EXPECT_EQ(notExitBunldleList.size(), 1);
}

/**
 * @tc.name: OnRestoreStart_Test_001
 * @tc.desc: Test OnRestoreStart function when profiles_ is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_001, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;

    // Ensure profiles_ is empty
    notificationCloneDisturb->profiles_.clear();

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Verify that the function returned without any action
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestoreStart_Test_002
 * @tc.desc: Test OnRestoreStart function when cloneDisturbQueue_ is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_002, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;

    // Ensure cloneDisturbQueue_ is null
    notificationCloneDisturb->cloneDisturbQueue_ = nullptr;

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Verify that the function returned without any action
    EXPECT_EQ(notificationCloneDisturb->cloneDisturbQueue_, nullptr);
}

/**
 * @tc.name: OnRestoreStart_Test_004
 * @tc.desc: Test OnRestoreStart function when trustList is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_004, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;

    // Add a profile to profiles_ with an empty trust list
    auto profile = NotificationDoNotDisturbProfile(1, "name", {});

    // Ensure cloneDisturbQueue_ is not null
    notificationCloneDisturb->cloneDisturbQueue_ = std::make_shared<ffrt::queue>("NotificationCloneDisturbQueue");

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Verify that the profile is deleted
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnUserSwitch_Test_001
 * @tc.desc: Test OnUserSwitch function when cloneDisturbQueue_ is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnUserSwitch_Test_001, Function | SmallTest | Level1)
{
    // Ensure cloneDisturbQueue_ is not null
    notificationCloneDisturb->cloneDisturbQueue_ = nullptr;

    // Call the function
    notificationCloneDisturb->OnUserSwitch(100);

    // Verify that the profile is deleted
    EXPECT_EQ(notificationCloneDisturb->cloneDisturbQueue_, nullptr);
}

/**
 * @tc.name: CheckBundleInfo_Test_001
 * @tc.desc: Test that when a matching bundle is found in trustList, it is added to bundleList and
 *           removed from trustList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_001, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    NotificationBundleOption matchingBundle;
    matchingBundle.SetBundleName("com.example.app");
    matchingBundle.SetAppIndex(1);
    trustList.push_back(matchingBundle);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 1);
    EXPECT_EQ(trustList.size(), 0);
    EXPECT_EQ(bundleList[0].GetBundleName(), "com.example.app");
    EXPECT_EQ(bundleList[0].GetAppIndex(), 1);
}

/**
 * @tc.name: CheckBundleInfo_Test_002
 * @tc.desc: Test that when no matching bundle is found in trustList, the bundle is not added to bundleList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_002, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    NotificationBundleOption nonMatchingBundle;
    nonMatchingBundle.SetBundleName("com.example.other");
    nonMatchingBundle.SetAppIndex(2);
    trustList.push_back(nonMatchingBundle);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 0);
    EXPECT_EQ(trustList.size(), 1);
}

/**
 * @tc.name: CheckBundleInfo_Test_003
 * @tc.desc: Test that when trustList is empty, the bundle is not added to bundleList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_003, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 0);
    EXPECT_EQ(trustList.size(), 0);
}